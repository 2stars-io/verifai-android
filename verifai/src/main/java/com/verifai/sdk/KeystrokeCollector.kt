package com.verifai.sdk

import android.app.Application
import android.os.SystemClock
import android.text.Editable
import android.text.TextWatcher
import android.widget.EditText
import java.security.MessageDigest

/**
 * Captures keystroke-dynamics flight time on text input fields.
 *
 * Flight time = ms between two consecutive characters arriving in the
 * field. Together with which fields the user types in (typically
 * username + password), this builds a session-average that's stable
 * across logins for the legitimate user but distinct between users —
 * the spouse case included, because muscle memory of your own password
 * makes inter-character timing characteristic to you.
 *
 * Why flight time only (no dwell time): Android's system IME runs in a
 * separate sandboxed process. The host app receives [TextWatcher.onTextChanged]
 * callbacks for character arrivals but never sees true KEY_DOWN /
 * KEY_UP events for system-keyboard input — those are owned by the
 * IME. Dwell time (how long a key is held down) is therefore only
 * available to apps that draw their own on-screen keyboard (PIN pads,
 * custom secure inputs). For a standard EditText + system keyboard
 * flow we get one timestamp per character: the moment the IME
 * committed it to the field. Inter-character intervals derived from
 * those timestamps are the flight-time signal.
 *
 * Single average is bucketed (10 buckets); production would benefit
 * from per-bigram stats, but adds 26²×timing-bytes to the wire and
 * needs a fixed character set assumption. The simple session-average
 * is a strong-enough first signal — it captures pace differences that
 * the wife-test scenario reliably trips.
 *
 * Threading: the TextWatcher callbacks fire on the main thread.
 * [getHashes] runs on Dispatchers.IO from DeviceManager. State is
 * guarded by an explicit lock.
 */
internal object KeystrokeCollector {

    /**
     * Bucket boundaries (ms) for average inter-key flight time.
     * Wide range covers everything from rapid typists (~80 ms/key) to
     * slow finger-search (>1 s/key, common on small touch keyboards).
     * Above 5 s the user paused — clamped at upper bucket.
     */
    private val FLIGHT_INTERVAL_BUCKETS = floatArrayOf(80f, 120f, 160f, 220f, 300f, 400f, 600f, 1000f, 2000f) // ms

    /** Don't count gaps longer than this — they're "user paused mid-
     *  password to look up", not flight time. */
    private const val MAX_FLIGHT_INTERVAL_MS = 5_000L

    /** Five character classes for the per-bigram-class signal. We
     *  deliberately use class — not raw character — so the hash never
     *  encodes the user's actual password content. */
    private const val CHAR_CLASS_VOWEL     = "v"
    private const val CHAR_CLASS_CONSONANT = "c"
    private const val CHAR_CLASS_DIGIT     = "d"
    private const val CHAR_CLASS_SYMBOL    = "y"
    private const val CHAR_CLASS_SPACE     = "s"

    private val lock = Any()
    private var initialised = false
    private var salt: String = ""

    private var flightSum = 0L
    private var flightCount = 0
    private var lastCharTimeMs = 0L

    // Variance accumulator — running sum of squared flight intervals.
    // Combined with flightSum + flightCount this gives us stddev in O(1)
    // at read time. Captures *consistency* of pace (a user who types in
    // a steady rhythm vs one who hunt-and-pecks fast then pauses).
    private var flightSumSq = 0.0

    // Per-bigram-class flight time aggregates. Key = "prevClass→currClass"
    // (e.g. "v→c", "c→d"). Value = (sum_ms, count). At session read we
    // identify the dominant class-pair (highest count) and hash its avg
    // flight time. This is a much stronger signature than the global avg
    // because the same user typically transitions between specific class
    // pairs the same way (e.g. consonant-to-vowel always ~100ms in their
    // muscle memory) while different users diverge.
    private val bigramTimes: HashMap<String, LongArray> = HashMap()  // key → [sum, count]
    private var prevCharClass: String? = null

    @Suppress("UNUSED_PARAMETER")
    fun init(application: Application, salt: String) {
        // application reserved for future use (per-Activity auto-attach
        // would let us bind to all EditTexts marked secure without host
        // app calling attachTo). For now we just stash the salt.
        synchronized(lock) {
            if (initialised) return
            this.salt = salt
            initialised = true
        }
    }

    /**
     * Install a TextWatcher on [editText] that records inter-character
     * flight times. Idempotent — re-attaching to the same EditText
     * stacks listeners harmlessly (they all record the same event), but
     * cheaper to call once per Activity onCreate.
     *
     * Call this in the host app's password / secure-input field
     * `onCreate`/`onCreateView`. Resetting averages between login
     * attempts is handled by [BehavioralCollector.resetSession].
     */
    fun attachTo(editText: EditText) {
        if (!initialised) return
        editText.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun afterTextChanged(s: Editable?) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                // Only count single-character INSERT events. Backspace
                // (count == 0, before > 0), paste (count > 1), and IME
                // composing replacements don't reflect typing rhythm.
                if (count != 1 || before != 0) {
                    // Reset the timer on edits other than single inserts —
                    // avoids charging "interval since last keystroke"
                    // against a backspace + retype sequence.
                    synchronized(lock) {
                        lastCharTimeMs = 0L
                        prevCharClass = null
                    }
                    return
                }
                val now = SystemClock.uptimeMillis()
                // Identify the class of the just-inserted character. `start`
                // is its position; defensive guard against out-of-range.
                val newChar: Char? = s?.getOrNull(start)
                val newClass: String? = newChar?.let { classifyChar(it) }
                synchronized(lock) {
                    if (lastCharTimeMs > 0L) {
                        val interval = now - lastCharTimeMs
                        if (interval in 1L..MAX_FLIGHT_INTERVAL_MS) {
                            flightSum += interval
                            flightSumSq += (interval.toDouble() * interval.toDouble())
                            flightCount++
                            // Per-bigram-class accumulator. Only records the
                            // pair when both ends are known — first character
                            // of a session has no preceding char.
                            val pc = prevCharClass
                            if (pc != null && newClass != null) {
                                val key = "$pc→$newClass"
                                val entry = bigramTimes.getOrPut(key) { longArrayOf(0L, 0L) }
                                entry[0] += interval
                                entry[1] += 1L
                            }
                        }
                    }
                    lastCharTimeMs = now
                    prevCharClass = newClass
                }
            }
        })
    }

    /**
     * Returns the session's keystroke hashes. Up to three categories:
     *
     *   - `keystroke`         — session-average flight time (existing
     *                            v1 signal, kept for back-compat)
     *   - `keystrokeStddev`   — stddev of flight times (new in 3.1.0;
     *                            captures how *consistent* the user's
     *                            pace is — a strong per-user signature
     *                            on top of the average pace)
     *   - `keystrokeBigram`   — dominant character-class-pair flight
     *                            (new in 3.1.0; bucketed by (class-pair,
     *                            time-bucket). Privacy-safe: encodes
     *                            character CLASS, not characters)
     *
     * Each category is independent — server can match any subset across
     * sessions. Categories with no samples are simply omitted; the
     * server treats absent entries as no-info.
     */
    fun getHashes(): Map<String, String> {
        if (!initialised) return emptyMap()
        synchronized(lock) {
            if (flightCount == 0 || salt.isEmpty()) return emptyMap()
            val out = HashMap<String, String>(3)

            // Existing: avg flight time.
            val avg = flightSum.toFloat() / flightCount
            out["keystroke"] = hashBucket(salt, "kflight", bucketIndex(avg, FLIGHT_INTERVAL_BUCKETS))

            // New: stddev of flight times. Welford-style variance from
            // running sums. Need >= 2 samples for a meaningful stddev.
            if (flightCount >= 2) {
                val mean = flightSum.toDouble() / flightCount
                val variance = (flightSumSq / flightCount) - (mean * mean)
                val stddev = if (variance > 0) kotlin.math.sqrt(variance).toFloat() else 0f
                // Reuse the same bucket boundaries — stddev and avg live
                // in comparable ms ranges so a single bucket family
                // works for both.
                out["keystrokeStddev"] = hashBucket(salt, "kstddev", bucketIndex(stddev, FLIGHT_INTERVAL_BUCKETS))
            }

            // New: dominant class-pair bigram. Pick the (class-pair) with
            // the most samples this session, hash its avg-flight bucket
            // joint with the class-pair label. If multiple pairs tie,
            // the iteration order picks one — deterministic enough across
            // sessions because the same user types the same password.
            if (bigramTimes.isNotEmpty()) {
                var topKey: String? = null
                var topCount = 0L
                var topSum = 0L
                for ((k, sumCount) in bigramTimes) {
                    if (sumCount[1] > topCount) {
                        topKey = k
                        topCount = sumCount[1]
                        topSum = sumCount[0]
                    }
                }
                if (topKey != null && topCount > 0) {
                    val avgPair = topSum.toFloat() / topCount.toFloat()
                    val bucket = bucketIndex(avgPair, FLIGHT_INTERVAL_BUCKETS)
                    // Join the class-pair label INTO the hash input so the
                    // same flight-time bucket on different class-pairs
                    // produces different hashes — server sees this as a
                    // 2D signal compressed to a single hash.
                    out["keystrokeBigram"] = hashBucket(salt, "kbigram:$topKey", bucket)
                }
            }
            return out
        }
    }

    fun resetSession() {
        synchronized(lock) {
            flightSum = 0L
            flightSumSq = 0.0
            flightCount = 0
            lastCharTimeMs = 0L
            prevCharClass = null
            bigramTimes.clear()
        }
    }

    /**
     * Debug snapshot for the test-bench BEHAVIORAL DEBUG button.
     * Returns (flight-time sample count, distinct bigram-class-pair count).
     * Both reset on resetSession() — i.e. after each verify call.
     */
    fun debugCounts(): Pair<Int, Int> = synchronized(lock) {
        flightCount to bigramTimes.size
    }

    /**
     * Five-way character classification used for the bigram signal. Kept
     * intentionally coarse so individual characters can't be backed out
     * of the resulting hash even by an attacker who knows the algorithm.
     */
    private fun classifyChar(c: Char): String = when {
        c.isWhitespace() -> CHAR_CLASS_SPACE
        c.isDigit()      -> CHAR_CLASS_DIGIT
        c in "aeiouAEIOU" -> CHAR_CLASS_VOWEL
        c.isLetter()     -> CHAR_CLASS_CONSONANT
        else             -> CHAR_CLASS_SYMBOL
    }

    private fun bucketIndex(value: Float, bounds: FloatArray): Int {
        for (i in bounds.indices) {
            if (value <= bounds[i]) return i
        }
        return bounds.size
    }

    private fun hashBucket(salt: String, category: String, bucket: Int): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(salt.toByteArray(Charsets.UTF_8))
        md.update(0)
        md.update(category.toByteArray(Charsets.UTF_8))
        md.update(0)
        md.update("b$bucket".toByteArray(Charsets.UTF_8))
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}
