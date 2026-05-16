package com.verifai.sdk

import android.app.Application
import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import java.security.MessageDigest
import kotlin.math.sqrt

/**
 * Captures an IMU-derived motion signature while the user is on a
 * sensitive screen (typically the login screen).
 *
 * Two statistical features are computed from the buffered samples:
 *
 *   - **amplitude** = stddev of accelerometer magnitude across the
 *     window. Captures gross motion: phone-on-table (very low) vs.
 *     hand-held standing (moderate) vs. walking / in-vehicle (high).
 *
 *   - **freqRatio** = sum-of-squared first-differences / sum-of-
 *     squared deviations. A coarse frequency-content proxy without
 *     needing FFT — high values mean the signal has lots of fast
 *     movement (jitter / tremor); low values mean slow drift. Stable
 *     within a person's hand but differs measurably between people
 *     (hand size, grip, posture, tremor frequency).
 *
 * Both features are independently bucketed and the (amp, freq) tuple
 * gets hashed into a single `motionTremor` category. The composite
 * gives 10×10 = 100 distinct buckets per person, which collapses
 * naturally to 1–3 buckets per individual user under the sliding-
 * window match rule.
 *
 * Lifecycle: the host app calls [start] when it wants sampling
 * (typically Activity.onResume of the login screen) and [stop] when
 * sampling should end (Activity.onPause or just before submit). The
 * sensor listener is unregistered on [stop] so battery cost is bounded
 * to the time the user is actually on the protected screen.
 *
 * Threading: SensorEventListener callbacks fire on the main thread by
 * default. State is guarded by an explicit lock; reads happen from
 * Dispatchers.IO during /verifyDevice payload assembly.
 */
internal object MotionCollector {

    /** Bucket boundaries for accel-magnitude stddev (m/s²).
     *  Tuned to span the realistic range from desk-resting (~0.05) to
     *  walking (~3.0) to in-vehicle (~6.0+). */
    private val AMP_BUCKETS = floatArrayOf(0.05f, 0.10f, 0.20f, 0.40f, 0.70f, 1.20f, 2.00f, 3.00f, 5.00f)

    /** Bucket boundaries for first-diff energy ratio (dimensionless,
     *  roughly 0..2). Higher = more high-frequency content per unit
     *  amplitude. */
    private val FREQ_BUCKETS = floatArrayOf(0.05f, 0.10f, 0.20f, 0.30f, 0.45f, 0.60f, 0.80f, 1.10f, 1.50f)

    /** Bucket boundaries for gyro-magnitude stddev (rad/s). Gyro range
     *  is roughly 0–7 rad/s for normal handheld use; phone in pocket
     *  while walking peaks around 0.2 rad/s; a deliberate hand wave
     *  hits 2–3 rad/s. */
    private val GYRO_AMP_BUCKETS = floatArrayOf(0.005f, 0.015f, 0.04f, 0.08f, 0.15f, 0.25f, 0.40f, 0.70f, 1.20f)

    /** Cap on stored samples — bounds memory + CPU on getHashes.
     *  At SENSOR_DELAY_GAME (~50 Hz) this is ~10 s of data. */
    private const val MAX_SAMPLES = 512

    /** Min samples before we attempt a hash. Below this, the signal
     *  is too short to be meaningful — fail open by returning no hash
     *  (server treats absent category as no-info). */
    private const val MIN_SAMPLES = 50

    private val lock = Any()
    private var initialised = false
    private var salt: String = ""
    private var sensorManager: SensorManager? = null
    private var accelSensor: Sensor? = null
    private var gyroSensor: Sensor? = null

    /** Ring of accel-magnitude samples (sqrt(x²+y²+z²)), m/s². */
    private val samples = FloatArray(MAX_SAMPLES)
    private var sampleCount = 0  // total written; min(MAX_SAMPLES, this) are valid in the ring
    /** Ring of gyro-magnitude samples (sqrt(x²+y²+z²)), rad/s. Same window
     *  semantics — independent of the accel ring so devices that have one
     *  sensor but not the other can still contribute the half they do. */
    private val gyroSamples = FloatArray(MAX_SAMPLES)
    private var gyroSampleCount = 0
    private var sampling = false

    private val listener = object : SensorEventListener {
        override fun onSensorChanged(event: SensorEvent) {
            val x = event.values[0]
            val y = event.values[1]
            val z = event.values[2]
            val mag = sqrt(x * x + y * y + z * z)
            when (event.sensor.type) {
                Sensor.TYPE_ACCELEROMETER -> synchronized(lock) {
                    samples[sampleCount % MAX_SAMPLES] = mag
                    sampleCount++
                }
                Sensor.TYPE_GYROSCOPE -> synchronized(lock) {
                    gyroSamples[gyroSampleCount % MAX_SAMPLES] = mag
                    gyroSampleCount++
                }
            }
        }

        override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
    }

    fun init(application: Application, salt: String) {
        synchronized(lock) {
            if (initialised) return
            this.salt = salt
            sensorManager = application.applicationContext
                .getSystemService(Context.SENSOR_SERVICE) as? SensorManager
            accelSensor = sensorManager?.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
            // TYPE_GYROSCOPE is the raw rotational-velocity sensor (rad/s).
            // Not all devices have one — older budget phones omit it. We
            // emit a gyro hash only when samples exist; absent gyro just
            // means that one category is missing from the payload, server
            // treats it as no-info.
            gyroSensor  = sensorManager?.getDefaultSensor(Sensor.TYPE_GYROSCOPE)
            initialised = true
        }
    }

    /**
     * Begin sampling. Idempotent — calling twice without an intervening
     * stop is harmless. No-op if init failed (no SensorManager / no
     * accelerometer on this device). Battery cost: ~50 Hz accel
     * subscription, which is the standard SENSOR_DELAY_GAME rate
     * commonly used by games. Negligible at the seconds-scale window
     * we sample on the login screen.
     */
    fun start() {
        synchronized(lock) {
            if (!initialised || sampling) return
            val sm = sensorManager ?: return
            // Register accel if available — gyro is optional. If neither
            // exists (extremely unlikely on a modern phone), the start()
            // becomes a no-op and getHashes() returns empty.
            accelSensor?.let { sm.registerListener(listener, it, SensorManager.SENSOR_DELAY_GAME) }
            gyroSensor?.let  { sm.registerListener(listener, it, SensorManager.SENSOR_DELAY_GAME) }
            sampling = (accelSensor != null || gyroSensor != null)
        }
    }

    /** Stop sampling. Safe to call when not sampling. */
    fun stop() {
        synchronized(lock) {
            if (!sampling) return
            // unregisterListener with no sensor arg removes ALL sensors
            // this listener is registered for — covers both accel + gyro
            // in one call.
            sensorManager?.unregisterListener(listener)
            sampling = false
        }
    }

    /**
     * Compute (amplitude, freqRatio) from the buffered samples and
     * return a single `motionTremor` hash. Empty if too few samples.
     */
    fun getHashes(): Map<String, String> {
        if (!initialised) return emptyMap()
        synchronized(lock) {
            if (salt.isEmpty()) return emptyMap()
            val out = HashMap<String, String>(2)

            // ---- motionTremor (accelerometer) ----
            val n = if (sampleCount >= MAX_SAMPLES) MAX_SAMPLES else sampleCount
            if (n >= MIN_SAMPLES) {
                val (amp, freq) = _ampAndFreq(samples, n)
                val ampB  = bucketIndex(amp,  AMP_BUCKETS)
                val freqB = bucketIndex(freq, FREQ_BUCKETS)
                // Composite index: 10 amp × 10 freq = 100 buckets, flat 0..99.
                val composite = ampB * (FREQ_BUCKETS.size + 1) + freqB
                out["motionTremor"] = hashBucket(salt, "tremor", composite)
            }

            // ---- gyroTremor (rotational velocity) — NEW in 3.1.0 ----
            // Independent signal from motionTremor: captures *rotational*
            // hand tremor while holding the phone (tilting to read,
            // wobble while typing), not linear acceleration. Phones can
            // sit perfectly still on a desk and gyroTremor is essentially
            // zero, while motionTremor for the same phone in-hand will
            // be moderate. Conversely, walking with the phone clipped to
            // a belt produces high motionTremor but low gyroTremor.
            val gn = if (gyroSampleCount >= MAX_SAMPLES) MAX_SAMPLES else gyroSampleCount
            if (gn >= MIN_SAMPLES) {
                val (gAmp, gFreq) = _ampAndFreq(gyroSamples, gn)
                val gAmpB  = bucketIndex(gAmp,  GYRO_AMP_BUCKETS)
                val gFreqB = bucketIndex(gFreq, FREQ_BUCKETS)
                val composite = gAmpB * (FREQ_BUCKETS.size + 1) + gFreqB
                out["gyroTremor"] = hashBucket(salt, "gyro", composite)
            }
            return out
        }
    }

    /** Compute (amplitude, freqRatio) over the first [n] entries of
     *  [buf]. Single-pass O(n). Returns (0, 0) for fewer than 2 samples
     *  or perfectly flat signal. */
    private fun _ampAndFreq(buf: FloatArray, n: Int): Pair<Float, Float> {
        var sum = 0f
        for (i in 0 until n) sum += buf[i]
        val mean = sum / n
        var sqDevSum = 0f
        var sqDiffSum = 0f
        for (i in 0 until n) {
            val d = buf[i] - mean
            sqDevSum += d * d
            if (i > 0) {
                val df = buf[i] - buf[i - 1]
                sqDiffSum += df * df
            }
        }
        val amplitude = sqrt(sqDevSum / n)
        val freqRatio = if (sqDevSum > 1e-6f) sqDiffSum / sqDevSum else 0f
        return amplitude to freqRatio
    }

    fun resetSession() {
        synchronized(lock) {
            sampleCount = 0
            gyroSampleCount = 0
        }
    }

    /** Debug helper for the test bench's BEHAVIORAL DEBUG panel. */
    fun debugSampleCounts(): Pair<Int, Int> = synchronized(lock) {
        sampleCount to gyroSampleCount
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
