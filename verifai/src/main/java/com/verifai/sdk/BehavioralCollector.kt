package com.verifai.sdk

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.os.SystemClock
import android.view.MotionEvent
import android.view.Window
import java.security.MessageDigest
import java.util.UUID
import kotlin.math.abs
import kotlin.math.sqrt

/**
 * Internal behavioral biometrics collector — companion to SignalCollector.
 *
 * Captures touch-derived signals that identify the *human* holding the
 * phone. Two more collectors live alongside this one and contribute
 * their own categories to the same payload:
 *
 *   - [KeystrokeCollector] — flight-time signature on password fields
 *   - [MotionCollector]    — IMU spectral signature (gyro/accel tremor)
 *
 * [getBehavioralHashes] aggregates all three into the map the server
 * expects on /registerDevice and /verifyDevice.
 *
 * Touch-derived categories produced here:
 *
 *   - **swipeVelocity** — avg px/ms during swipes (ACTION_DOWN →
 *     ACTION_MOVE → ACTION_UP with displacement > 32 px).
 *
 *   - **tapPressure** — avg contact "pressure". Probed at runtime: if
 *     the device reports meaningful [MotionEvent.getPressure] values
 *     (anything other than the stock 1.0f placeholder), we use that;
 *     otherwise we fall back to [MotionEvent.getSize] (touch radius).
 *     Both end up under the same `tapPressure` key on the wire — the
 *     bucket boundaries differ but the server doesn't care.
 *
 *   - **buttonRhythm** — avg ms between consecutive ACTION_UP events
 *     within the session. Captures how the user paces through the app.
 *
 *   - **swipeCurvature** — chord-to-path ratio over swipes. 1.0 = ruler-
 *     straight line, lower = arc. Hand anatomy + motor control make
 *     this stable per user and distinct between users.
 *
 *   - **multiTouchSpread** — max distance between any two simultaneous
 *     contact points during a multi-touch gesture. Hand-size dependent.
 *     Often absent in a single-finger login flow; if absent, server
 *     skips the category (no false-block on missing data).
 *
 * Each metric is averaged across the session, bucketed (10 buckets),
 * salted with the device-specific salt, and SHA-256'd before leaving
 * the device. The server never sees the raw averages.
 *
 * Threading: touch events arrive on the main UI thread; the public
 * read methods run on Dispatchers.IO from DeviceManager. Mutations are
 * guarded by an explicit lock — synchronized blocks instead of
 * @Synchronized because data classes / Maps don't inherit class-level
 * monitors cleanly.
 */
internal object BehavioralCollector {

    // ---- Constants ---------------------------------------------------

    /** Min displacement (in screen px) before a touch counts as a swipe. */
    private const val SWIPE_MIN_DISPLACEMENT_PX = 32f

    /** Max time (ms) between consecutive button presses to count as a
     *  rhythm interval. Anything longer = the user paused / left the app
     *  / put the phone down, so it's noise rather than rhythm. */
    private const val MAX_RHYTHM_INTERVAL_MS = 10_000L

    /** Bucket count per category. 10 buckets (= 9 boundaries) chosen
     *  to give ~10x finer-grained discrimination than the original
     *  5-bucket scheme while still being coarse enough that a single
     *  user's session-to-session variation lands in 2–3 adjacent
     *  buckets (which then fill the 10-entry sliding window naturally). */
    private val SWIPE_VELOCITY_BUCKETS    = floatArrayOf(0.15f, 0.30f, 0.45f, 0.60f, 0.80f, 1.00f, 1.25f, 1.60f, 2.00f) // px/ms
    private val TAP_SIZE_BUCKETS          = floatArrayOf(0.02f, 0.04f, 0.06f, 0.08f, 0.10f, 0.12f, 0.15f, 0.18f, 0.22f) // 0..1
    private val TAP_PRESSURE_BUCKETS      = floatArrayOf(0.10f, 0.20f, 0.30f, 0.40f, 0.50f, 0.60f, 0.70f, 0.80f, 0.90f) // 0..~1

    /** Touch heat-map: 5x5 grid (25 cells). Cell indices 0..24, row-major,
     *  with cell (col=0, row=0) = top-left. Tracks which screen region the
     *  user habitually taps in. Different users tap different parts of the
     *  same screen (depending on thumb length, dominant hand, app layout
     *  preference) — and a fraud attempt where a different person uses the
     *  same device often shows up as a different heat-map shape. */
    private const val TOUCH_HEATMAP_GRID = 5
    private const val TOUCH_HEATMAP_CELLS = TOUCH_HEATMAP_GRID * TOUCH_HEATMAP_GRID
    private val RHYTHM_INTERVAL_BUCKETS   = floatArrayOf(200f, 400f, 600f, 800f, 1200f, 1500f, 2000f, 3000f, 5000f)     // ms
    private val SWIPE_CURVATURE_BUCKETS   = floatArrayOf(0.70f, 0.80f, 0.85f, 0.90f, 0.92f, 0.94f, 0.96f, 0.97f, 0.98f) // chord/path
    private val MULTI_TOUCH_SPREAD_BUCKETS = floatArrayOf(80f, 150f, 200f, 250f, 300f, 400f, 500f, 700f, 1000f)         // px

    // ---- State -------------------------------------------------------

    private val lock = Any()

    private lateinit var appContext: android.content.Context
    private var deviceSalt: String? = null
    private var initialised = false

    // Running averages — stored as (sum, count) pairs so we can fold in
    // new samples in O(1) and read the average lazily without locking.
    private var swipeSum = 0f
    private var swipeCount = 0
    private var tapSizeSum = 0f
    private var tapSizeCount = 0
    private var tapPressureSum = 0f
    private var tapPressureCount = 0
    private var rhythmSum = 0L
    private var rhythmCount = 0
    private var curvatureSum = 0f
    private var curvatureCount = 0
    private var multiTouchSpreadSum = 0f
    private var multiTouchSpreadCount = 0

    // Once we see a MotionEvent reporting pressure != 1.0f on this
    // device we trust getPressure() going forward (and bucket against
    // TAP_PRESSURE_BUCKETS). Until then we fall back to size, which
    // is universally reported across all Android devices.
    private var pressureIsMeaningful = false

    // Active gesture state — lives between an ACTION_DOWN and the
    // matching ACTION_UP / ACTION_CANCEL. Reset on every new gesture.
    private var gestureStartX = 0f
    private var gestureStartY = 0f
    private var gestureStartTimeMs = 0L
    private var gestureMaxDisplacement = 0f
    private var gestureInProgress = false
    private var lastUpTimeMs = 0L

    // Swipe-curvature accumulators: track path length (sum of segment
    // distances during MOVE) and the last sampled point. Chord at UP =
    // distance(start, current). ratio = chord / pathLength.
    private var gestureLastX = 0f
    private var gestureLastY = 0f
    private var gesturePathLength = 0f

    // Multi-touch max spread during the current gesture (px). Updated
    // any time we see >=2 pointers down. Reset on ACTION_DOWN / CANCEL.
    private var gestureMaxMultiSpread = 0f

    // Touch heat-map: per-cell tap counter (5x5 grid). Filled only on
    // ACTION_UP where the gesture classified as a tap (displacement
    // < SWIPE_MIN_DISPLACEMENT_PX). The cached screen dims are read
    // lazily from the first event with a real source — Activity-bound
    // dispatchTouchEvent doesn't carry screen info directly so we look
    // up display metrics from appContext at hash time.
    private val touchHeatmap = IntArray(TOUCH_HEATMAP_CELLS)
    private var touchHeatmapTotal = 0

    // ---- Lifecycle ---------------------------------------------------

    /**
     * Initialise the collector. Idempotent — safe to call multiple
     * times. Also installs an auto-capture lifecycle callback that
     * hooks each Activity's window so the host app doesn't need to
     * manually forward touches, and initialises [KeystrokeCollector] +
     * [MotionCollector] so the full behavioral payload is available.
     */
    fun init(application: Application) {
        synchronized(lock) {
            if (initialised) return
            appContext = application.applicationContext

            // Re-use the same persistent salt as SignalCollector so a user
            // can't be re-identified by switching between hash families.
            // SignalCollector creates the salt on first init; we just read
            // it here. If SignalCollector hasn't been initialised yet, we
            // mint our own (it'll get reused next time).
            val prefs = appContext.getSharedPreferences("verifai_internal", android.content.Context.MODE_PRIVATE)
            deviceSalt = prefs.getString("device_salt", null) ?: run {
                val s = UUID.randomUUID().toString()
                prefs.edit().putString("device_salt", s).apply()
                s
            }

            application.registerActivityLifecycleCallbacks(LifecycleHook)
            initialised = true
        }

        // Sibling collectors share the same salt + lifecycle. Init them
        // outside the lock — they manage their own locks.
        KeystrokeCollector.init(application, salt = deviceSalt ?: "")
        MotionCollector.init(application, salt = deviceSalt ?: "")
    }

    /**
     * Record a single MotionEvent. Called either:
     *   - automatically via the Window.Callback wrapper installed in
     *     [LifecycleHook] (no host-app changes needed), or
     *   - manually from a host Activity that overrides dispatchTouchEvent
     *     (useful when an app subclasses Window.Callback itself and the
     *     wrapper would interfere).
     *
     * Idempotent if [init] was never called — silently does nothing.
     * Touch-event hot path: must stay allocation-free in the common case.
     */
    fun recordTouch(ev: MotionEvent) {
        if (!initialised) return
        synchronized(lock) {
            // Pressure probe — runs on every event regardless of action.
            // Once we see a real value, lock the flag in until process
            // restart. Tiny overhead, fires at most once per device.
            if (!pressureIsMeaningful) {
                val p = ev.pressure
                if (p > 0f && p != 1.0f) pressureIsMeaningful = true
            }

            when (ev.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    gestureInProgress = true
                    gestureStartX = ev.x
                    gestureStartY = ev.y
                    gestureLastX = ev.x
                    gestureLastY = ev.y
                    gesturePathLength = 0f
                    gestureStartTimeMs = SystemClock.uptimeMillis()
                    gestureMaxDisplacement = 0f
                    gestureMaxMultiSpread = 0f
                }

                MotionEvent.ACTION_MOVE -> {
                    if (!gestureInProgress) return
                    // Displacement from start (max over the gesture).
                    val dx = ev.x - gestureStartX
                    val dy = ev.y - gestureStartY
                    val d = sqrt(dx * dx + dy * dy)
                    if (d > gestureMaxDisplacement) gestureMaxDisplacement = d

                    // Incremental path length — accumulate segment distance
                    // from the previous sampled point. Sum across the
                    // gesture gives the curvature denominator.
                    val sx = ev.x - gestureLastX
                    val sy = ev.y - gestureLastY
                    gesturePathLength += sqrt(sx * sx + sy * sy)
                    gestureLastX = ev.x
                    gestureLastY = ev.y

                    // Multi-touch spread — sample whenever we have ≥2
                    // pointers down. Cheap pairwise max; pointer count
                    // is almost always 2 in practice (zoom/pinch).
                    val n = ev.pointerCount
                    if (n >= 2) {
                        val s = maxPointerSpread(ev)
                        if (s > gestureMaxMultiSpread) gestureMaxMultiSpread = s
                    }
                }

                MotionEvent.ACTION_POINTER_DOWN -> {
                    // Additional finger landed mid-gesture. Sample spread
                    // immediately so a quick pinch still records.
                    val s = maxPointerSpread(ev)
                    if (s > gestureMaxMultiSpread) gestureMaxMultiSpread = s
                }

                MotionEvent.ACTION_UP -> {
                    if (!gestureInProgress) return
                    val now = SystemClock.uptimeMillis()
                    val durationMs = (now - gestureStartTimeMs).coerceAtLeast(1L)

                    if (gestureMaxDisplacement >= SWIPE_MIN_DISPLACEMENT_PX) {
                        // Treat as swipe — record velocity + curvature.
                        val velocity = gestureMaxDisplacement / durationMs.toFloat()
                        swipeSum += velocity
                        swipeCount++

                        // Curvature = straight-line distance / actual path
                        // length. Approaches 1 for ruler-straight swipes,
                        // drops for arced/zigzag swipes. Guard against
                        // div-by-zero — if pathLength came out tiny it
                        // shouldn't really qualify as a swipe anyway.
                        if (gesturePathLength > SWIPE_MIN_DISPLACEMENT_PX) {
                            val chord = gestureMaxDisplacement
                            val ratio = (chord / gesturePathLength).coerceIn(0f, 1f)
                            curvatureSum += ratio
                            curvatureCount++
                        }
                    } else {
                        // Treat as tap — record contact size + (real
                        // pressure when available) + rhythm interval +
                        // heat-map cell.
                        val size = ev.size.coerceIn(0f, 1f)
                        tapSizeSum += size
                        tapSizeCount++
                        val pressure = ev.pressure
                        if (pressure > 0f && pressure != 1.0f) {
                            tapPressureSum += pressure.coerceIn(0f, 1f)
                            tapPressureCount++
                        }
                        if (lastUpTimeMs > 0L) {
                            val interval = now - lastUpTimeMs
                            // Cap at MAX_RHYTHM_INTERVAL_MS — longer
                            // intervals are pauses, not rhythm, and would
                            // skew the average toward the upper bucket.
                            if (interval in 1L..MAX_RHYTHM_INTERVAL_MS) {
                                rhythmSum += interval
                                rhythmCount++
                            }
                        }
                        lastUpTimeMs = now

                        // Heat-map: bucket the tap location into 5x5 grid.
                        // Use the appContext display metrics for screen
                        // size — accurate enough for the cell granularity
                        // we need, and avoids depending on per-event
                        // window dims (multi-window mode could lie).
                        val dm = appContext.resources.displayMetrics
                        val sw = dm.widthPixels.coerceAtLeast(1)
                        val sh = dm.heightPixels.coerceAtLeast(1)
                        val col = ((ev.x / sw) * TOUCH_HEATMAP_GRID).toInt().coerceIn(0, TOUCH_HEATMAP_GRID - 1)
                        val row = ((ev.y / sh) * TOUCH_HEATMAP_GRID).toInt().coerceIn(0, TOUCH_HEATMAP_GRID - 1)
                        val cell = row * TOUCH_HEATMAP_GRID + col
                        touchHeatmap[cell]++
                        touchHeatmapTotal++
                    }

                    // If multi-touch happened during this gesture, record
                    // the max spread regardless of swipe/tap classification.
                    if (gestureMaxMultiSpread > 0f) {
                        multiTouchSpreadSum += gestureMaxMultiSpread
                        multiTouchSpreadCount++
                    }
                    gestureInProgress = false
                }

                MotionEvent.ACTION_CANCEL -> {
                    gestureInProgress = false
                }
            }
        }
    }

    /**
     * Compute the SHA-256 hash of the bucket label for each behavioral
     * category, salted with the same device salt SignalCollector uses,
     * and merge in the sibling collectors' contributions ([KeystrokeCollector],
     * [MotionCollector]).
     *
     * Returns no entry for any category with zero samples in the current
     * session — the server treats absent categories as "no info, don't
     * compare". This is the right default: an SDK user who completes a
     * verify before doing any swiping shouldn't have their behavioral
     * check fire on stale / fabricated data.
     *
     * Reading the averages does NOT clear them — call [resetSession]
     * explicitly when you want to start a fresh capture window
     * (typically right after a successful verify completes).
     */
    fun getBehavioralHashes(): Map<String, String> {
        if (!initialised) return emptyMap()
        val out = HashMap<String, String>(7)
        synchronized(lock) {
            val salt = deviceSalt ?: return emptyMap()

            if (swipeCount > 0) {
                val avg = swipeSum / swipeCount
                out["swipeVelocity"] = hashBucket(salt, "swipe", bucketIndex(avg, SWIPE_VELOCITY_BUCKETS))
            }

            // tapPressure: use real pressure samples when meaningful;
            // otherwise size. The category key is the same on the wire —
            // bucket families are different but both map to "tapPressure"
            // so a device that gains a fresh OS update with proper
            // pressure reporting smoothly switches its bucket family.
            // (Window rotation absorbs the transition naturally over
            // ~10 logins.)
            if (pressureIsMeaningful && tapPressureCount > 0) {
                val avg = tapPressureSum / tapPressureCount
                out["tapPressure"] = hashBucket(salt, "tapP", bucketIndex(avg, TAP_PRESSURE_BUCKETS))
            } else if (tapSizeCount > 0) {
                val avg = tapSizeSum / tapSizeCount
                out["tapPressure"] = hashBucket(salt, "tapS", bucketIndex(avg, TAP_SIZE_BUCKETS))
            }

            if (rhythmCount > 0) {
                val avg = rhythmSum.toFloat() / rhythmCount
                out["buttonRhythm"] = hashBucket(salt, "rhythm", bucketIndex(avg, RHYTHM_INTERVAL_BUCKETS))
            }

            if (curvatureCount > 0) {
                val avg = curvatureSum / curvatureCount
                out["swipeCurvature"] = hashBucket(salt, "curve", bucketIndex(avg, SWIPE_CURVATURE_BUCKETS))
            }

            if (multiTouchSpreadCount > 0) {
                val avg = multiTouchSpreadSum / multiTouchSpreadCount
                out["multiTouchSpread"] = hashBucket(salt, "mtspread", bucketIndex(avg, MULTI_TOUCH_SPREAD_BUCKETS))
            }

            // Touch heat-map: identify the top-3 most-tapped cells in the
            // session, sort the cell indices ascending, and hash the tuple.
            // Why top-3 specifically: stable enough across sessions for the
            // same user (their thumb naturally lands in the same screen
            // regions), but coarse enough that a slightly different layout
            // or one-handed-vs-two-handed session still produces the same
            // dominant cells. Min sample threshold prevents the cold-start
            // case (1–2 taps) from producing a spurious signature.
            if (touchHeatmapTotal >= 5) {
                // O(25 log 25) — trivially small.
                val indexed = (0 until TOUCH_HEATMAP_CELLS)
                    .map { it to touchHeatmap[it] }
                    .filter { it.second > 0 }
                    .sortedByDescending { it.second }
                val top = indexed.take(3).map { it.first }.sorted()
                if (top.isNotEmpty()) {
                    val label = "heatmap:" + top.joinToString(",")
                    out["touchRegion"] = hashBucket(salt, label, /*bucket*/0)
                }
            }
        }

        // Merge sibling collectors. Their getHashes() are no-ops if init
        // wasn't called or no samples were captured.
        out.putAll(KeystrokeCollector.getHashes())
        out.putAll(MotionCollector.getHashes())
        return out
    }

    /**
     * Clear all running averages across all three collectors. Call after
     * a successful verify or register so the next call's hashes reflect
     * only the next session. Without this, the running average drifts
     * toward the lifetime mean and recent-session changes wash out.
     */
    fun resetSession() {
        synchronized(lock) {
            swipeSum = 0f; swipeCount = 0
            tapSizeSum = 0f; tapSizeCount = 0
            tapPressureSum = 0f; tapPressureCount = 0
            rhythmSum = 0L; rhythmCount = 0
            curvatureSum = 0f; curvatureCount = 0
            multiTouchSpreadSum = 0f; multiTouchSpreadCount = 0
            lastUpTimeMs = 0L
            gestureInProgress = false
            gesturePathLength = 0f
            gestureMaxMultiSpread = 0f
            // Heat-map: clear cell counters so the next session starts
            // fresh. Same window-reset rationale as the other categories.
            for (i in touchHeatmap.indices) touchHeatmap[i] = 0
            touchHeatmapTotal = 0
        }
        KeystrokeCollector.resetSession()
        MotionCollector.resetSession()
    }

    /** Snapshot of current sample counts — useful for the sample app's
     *  "Training: 3/10" indicator and for diagnostic logging. */
    fun debugSampleCounts(): Triple<Int, Int, Int> = synchronized(lock) {
        Triple(swipeCount, (if (pressureIsMeaningful) tapPressureCount else tapSizeCount), rhythmCount)
    }

    // ---- Helpers -----------------------------------------------------

    /**
     * Return the bucket index (0..bounds.size) for [value] given an
     * ascending-sorted [bounds] array. Bucket 0 = value <= bounds[0];
     * bucket bounds.size = value > bounds[bounds.size-1].
     */
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

    /**
     * Max pairwise distance between any two simultaneous contact points
     * in [ev]. Returns 0 if fewer than 2 pointers. O(n²) but n is rarely
     * over 2 in practice (zoom/pinch); 3+ is a rare power-user gesture.
     */
    private fun maxPointerSpread(ev: MotionEvent): Float {
        val n = ev.pointerCount
        if (n < 2) return 0f
        var max = 0f
        for (i in 0 until n - 1) {
            val xi = ev.getX(i); val yi = ev.getY(i)
            for (j in i + 1 until n) {
                val xj = ev.getX(j); val yj = ev.getY(j)
                val dx = xi - xj; val dy = yi - yj
                val d = sqrt(dx * dx + dy * dy)
                if (d > max) max = d
            }
        }
        return max
    }

    // ---- Auto-capture: Activity + Window.Callback wrapper ------------

    /**
     * Wraps each Activity's Window.Callback so dispatchTouchEvent flows
     * through us without disrupting the existing handler chain. The
     * delegate pattern is forward-compatible with any Window.Callback
     * implementation the host app or framework installs.
     */
    private object LifecycleHook : Application.ActivityLifecycleCallbacks {
        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
            val window = activity.window ?: return
            val original = window.callback ?: return
            // Idempotency — don't double-wrap if we re-enter.
            if (original is TouchInterceptingCallback) return
            window.callback = TouchInterceptingCallback(original)
        }

        override fun onActivityStarted(activity: Activity) {}
        override fun onActivityResumed(activity: Activity) {}
        override fun onActivityPaused(activity: Activity) {}
        override fun onActivityStopped(activity: Activity) {}
        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
        override fun onActivityDestroyed(activity: Activity) {}
    }

    /**
     * Window.Callback delegate that forwards every dispatched MotionEvent
     * to [recordTouch] before the framework dispatches it to views. We
     * never consume the event — return value is whatever the wrapped
     * callback returns. Read-only intercept.
     */
    private class TouchInterceptingCallback(private val inner: Window.Callback) : Window.Callback by inner {
        override fun dispatchTouchEvent(event: MotionEvent): Boolean {
            try { recordTouch(event) } catch (_: Throwable) {
                // Touch hot path — never propagate collector failures to
                // the UI dispatch chain. A bad sample is better than a
                // crashed app.
            }
            return inner.dispatchTouchEvent(event)
        }
    }
}
