package com.verifai.sdk

import android.app.Application
import android.content.Context
import android.widget.EditText
import kotlinx.coroutines.*

/**
 * VerifAI SDK - Zero-Knowledge Device Trust
 * 
 * Usage:
 * ```
 * // Initialize once in Application or MainActivity
 * VerifAI.init(context, "vf_live_your_api_key")
 * 
 * // Register device (first login)
 * val result = VerifAI.register("user@email.com")
 * if (result.success) { /* proceed */ }
 * 
 * // Verify device (subsequent logins)
 * val result = VerifAI.verify("user@email.com")
 * when (result.status) {
 *     VerifAI.Status.TRUSTED -> { /* allow access */ }
 *     VerifAI.Status.NEW_DEVICE -> { /* show approval UI */ }
 *     VerifAI.Status.REJECTED -> { /* block access */ }
 * }
 * ```
 */
object VerifAI {

    /** SDK build version — sent as User-Agent and used in error reporting. */
    const val SDK_VERSION = "3.2.0"

    private lateinit var config: Config
    private var isInitialized = false

    // Host opts in to ship hashed contacts on every register/verify by
    // calling [setContactLockEnabled]. Default OFF so existing integrators
    // are not surprised by an unexpected contact-list read. The READ_CONTACTS
    // permission still has to be granted at the system level — the SDK
    // silently uploads zero hashes if the permission isn't held.
    private var contactLockEnabled = false

    /**
     * Initialize the SDK. Call once at app startup.
     *
     * @param context Application context
     * @param apiKey Your 2stars API key. v3.0+ uses `hbs_live_…` (the same
     *               key as Video AI). Legacy `vf_live_…` / `vf_test_…` keys
     *               are still accepted during the migration window — they
     *               require the operator to deploy the legacy compatibility
     *               shim on the server.
     * @param options Optional configuration
     */
    fun init(context: Context, apiKey: String, options: Options = Options()) {
        require(
            apiKey.startsWith("hbs_live_") ||
            apiKey.startsWith("hbs_test_") ||
            apiKey.startsWith("vf_live_") ||
            apiKey.startsWith("vf_test_")
        ) {
            "Invalid API key format. Must start with hbs_live_, hbs_test_, vf_live_, or vf_test_"
        }

        config = Config(
            context = context.applicationContext,
            apiKey = apiKey,
            options = options
        )

        SignalCollector.init(context.applicationContext)

        // Behavioral biometrics — auto-installed if init() was passed an
        // Application context (which is the common path: most apps call
        // VerifAI.init from their Application.onCreate or from the first
        // Activity, where applicationContext returns the Application).
        // Falls back gracefully if somehow called with a non-Application
        // context — behavioral capture just won't happen and the SDK
        // works as before, just without the third axis.
        val app = context.applicationContext as? Application
        if (app != null) {
            BehavioralCollector.init(app)
        }
        isInitialized = true
    }
    
    /**
     * Register a new device for the user.
     * Call this on first login / sign up.
     * 
     * @param userId User's email address
     * @return RegistrationResult with success status and device ID
     */
    suspend fun register(userId: String): RegistrationResult {
        checkInitialized()
        return DeviceManager.register(config, userId)
    }
    
    /**
     * Verify the current device against stored profile.
     * Call this on every login.
     * 
     * @param userId User's email address
     * @return VerificationResult with status and trust score
     */
    suspend fun verify(userId: String): VerificationResult {
        checkInitialized()
        return DeviceManager.verify(config, userId)
    }
    
    /**
     * Get trust score for the current device.
     * 
     * @param userId User's email address
     * @return TrustScore with level and numeric score
     */
    suspend fun getTrustScore(userId: String): TrustScore {
        checkInitialized()
        return DeviceManager.getTrustScore(config, userId)
    }
    
    /**
     * Register FCM token for push notifications.
     * Required for approving logins from other devices.
     * 
     * @param userId User's email address
     * @param fcmToken Firebase Cloud Messaging token
     */
    suspend fun registerPushToken(userId: String, fcmToken: String): Boolean {
        checkInitialized()
        return ApiClient.registerToken(config, userId, fcmToken)
    }
    
    /**
     * List all trusted devices for the user.
     * 
     * @param userId User's email address
     * @return List of trusted devices
     */
    suspend fun listDevices(userId: String): List<Device> {
        checkInitialized()
        return ApiClient.listDevices(config, userId)
    }
    
    /**
     * Remove a trusted device.
     * 
     * @param deviceId Device ID to remove
     * @param type Device type (pc or android)
     */
    suspend fun removeDevice(deviceId: String, type: DeviceType = DeviceType.ANDROID): Boolean {
        checkInitialized()
        return ApiClient.deleteDevice(config, deviceId, type)
    }

    /**
     * SIM-swap OTP gate. Runs the full VerifAI scan (deviceIdHash +
     * signals + behavioral) and answers whether the current device is
     * the one enrolled for `userId`. Call this BEFORE dispatching any
     * SMS/email OTP: if `allow == false`, the requesting phone isn't
     * the enrolled one (right code, wrong phone — the SIM-swap case),
     * so don't send.
     *
     * Stateless — no code is generated, no SMS is sent. Merchant keeps
     * its own OTP provider. Blocked results fire the server-side
     * `otp.blocked` webhook with the phone masked to last-4.
     *
     * @param userId       Same identifier used for register/verify
     * @param phoneNumber  E.164 (e.g. "+447700900123") — echoed to
     *                     the webhook on block, masked to last-4
     */
    suspend fun otpGate(userId: String, phoneNumber: String): OtpGateResult {
        checkInitialized()
        return DeviceManager.otpGate(config, userId, phoneNumber)
    }

    /**
     * Reset every enrolled device + pending session for `userId`
     * under this API key. Idempotent. Fires `verifai.reset` webhook
     * on the server so support/audit pipelines catch the action.
     */
    suspend fun resetUser(userId: String): ResetResult {
        checkInitialized()
        return DeviceManager.resetUser(config, userId)
    }

    /**
     * Surgical single-device reset. Use when the user has multiple
     * enrolled devices and only one (a stolen phone, a lost tablet)
     * needs to go.
     */
    suspend fun resetDevice(userId: String, deviceIdHash: String): ResetResult {
        checkInitialized()
        return DeviceManager.resetDevice(config, userId, deviceIdHash)
    }
    
    /**
     * Handle incoming push notification for device approval.
     * Call this from your FirebaseMessagingService.
     * 
     * @param data FCM message data
     * @return ApprovalRequest if this is an approval request, null otherwise
     */
    fun handlePushNotification(data: Map<String, String>): ApprovalRequest? {
        val type = data["type"] ?: return null
        
        return when (type) {
            "pc_approval", "android_approval" -> {
                ApprovalRequest(
                    sessionId = data["sessionId"] ?: return null,
                    type = if (type == "pc_approval") DeviceType.PC else DeviceType.ANDROID,
                    deviceInfo = data["browser"] ?: data["deviceModel"] ?: "Unknown",
                    publicIP = data["publicIP"] ?: ""
                )
            }
            else -> null
        }
    }
    
    /**
     * Approve a pending device request.
     * 
     * @param sessionId Session ID from ApprovalRequest
     * @param type Device type
     */
    suspend fun approveDevice(sessionId: String, type: DeviceType = DeviceType.PC): Boolean {
        checkInitialized()
        return ApiClient.approveDevice(config, sessionId, type)
    }
    
    /**
     * Reject a pending device request.
     * 
     * @param sessionId Session ID from ApprovalRequest
     * @param type Device type
     * @param reason Rejection reason
     */
    suspend fun rejectDevice(sessionId: String, type: DeviceType = DeviceType.PC, reason: String = "rejected_by_user"): Boolean {
        checkInitialized()
        return ApiClient.rejectDevice(config, sessionId, type, reason)
    }
    
    /**
     * Fetch the current state of an approval session. Returns null on
     * transport error; the caller (typically [pollSession]) retries.
     */
    suspend fun getSession(sessionId: String): SessionState? {
        checkInitialized()
        return ApiClient.getSession(config, sessionId)
    }

    /**
     * Wait for a NEW_DEVICE approval session to resolve. Polls
     * [getSession] every [intervalMs] until status moves off "pending"
     * or [deadlineMs] elapses. Returns the final session state, or a
     * synthetic `status="timeout"` entry on deadline.
     *
     * Used on the new-device side immediately after [verify] returned
     * NEW_DEVICE with a sessionId: the user's trusted device sees the
     * approval modal (FCM push + polling fallback on web), taps Approve
     * or Deny, and this resolves accordingly.
     */
    suspend fun pollSession(
        sessionId: String,
        intervalMs: Long = 2000L,
        deadlineMs: Long = 25_000L,
    ): SessionState {
        checkInitialized()
        val end = System.currentTimeMillis() + deadlineMs
        while (System.currentTimeMillis() < end) {
            val s = ApiClient.getSession(config, sessionId)
            if (s != null && s.status != "pending") return s
            kotlinx.coroutines.delay(intervalMs)
        }
        return SessionState(id = sessionId, status = "timeout")
    }

    /**
     * Check if this device is on the same network as a given IP.
     * Used for proximity verification.
     *
     * @param remoteIP The IP to compare against
     * @return true if on same network
     */
    suspend fun isSameNetwork(remoteIP: String): Boolean {
        val myIP = NetworkUtils.getPublicIP()
        return myIP == remoteIP
    }
    
    private fun checkInitialized() {
        check(isInitialized) { "VerifAI SDK not initialized. Call VerifAI.init() first." }
    }

    /**
     * Snapshot the current behavioral session — useful for rendering a
     * "Training: 3/5" indicator or a "we've seen 12 swipes this session"
     * debug counter without waiting for the next verify response.
     *
     * Counts are *session-local* and reset by every successful register
     * or verify call. If you call this immediately after [verify] you'll
     * see zero samples until the user resumes interacting.
     */
    /**
     * Live counts of behavioral-biometric samples captured in the
     * current session, across every collector. All counts reset on a
     * successful register/verify. Use this from a debug screen to
     * verify the SDK is actually picking up user interaction.
     */
    data class BehavioralCapture(
        val swipeCount:    Int,     // swipes recorded (BehavioralCollector)
        val tapCount:      Int,     // taps recorded — pressure/size + heat-map
        val rhythmCount:   Int,     // inter-tap rhythm samples
        val accelSamples:  Int = 0, // accelerometer readings (motionTremor)
        val gyroSamples:   Int = 0, // gyroscope readings (gyroTremor — 3.1.0+)
        val keystrokeCount: Int = 0, // keystroke flight-time samples
        val bigramCount:    Int = 0, // distinct character-class bigrams seen
    ) {
        val isReady: Boolean get() =
            swipeCount > 0 || tapCount > 0 || rhythmCount > 0 ||
            accelSamples > 0 || gyroSamples > 0 ||
            keystrokeCount > 0 || bigramCount > 0
    }

    fun getBehavioralCapture(): BehavioralCapture {
        val (s, t, r) = BehavioralCollector.debugSampleCounts()
        val (accel, gyro) = MotionCollector.debugSampleCounts()
        val ks = KeystrokeCollector.debugCounts()
        return BehavioralCapture(
            swipeCount     = s,
            tapCount       = t,
            rhythmCount    = r,
            accelSamples   = accel,
            gyroSamples    = gyro,
            keystrokeCount = ks.first,
            bigramCount    = ks.second,
        )
    }

    /**
     * Attach the keystroke-dynamics TextWatcher to a password-style
     * [EditText]. Records inter-character flight time as a behavioral
     * signal. Call this once per Activity that owns a sensitive input
     * field (typically in `onCreate`, after view binding).
     *
     * Safe to call from any thread, but TextWatcher events themselves
     * fire on the main thread.
     */
    fun attachPasswordField(editText: EditText) {
        KeystrokeCollector.attachTo(editText)
    }

    /**
     * Begin sampling the accelerometer for the motion-tremor signal.
     * Typically called in the login Activity's `onResume`. Pairs with
     * [stopMotionCapture] in `onPause`. Idempotent (extra calls are
     * cheap no-ops). Battery cost is bounded to the time the user is
     * on the screen — about a 50 Hz accel subscription, which Android
     * games happily run continuously.
     */
    fun startMotionCapture() {
        MotionCollector.start()
    }

    /**
     * Stop the accelerometer sampling started by [startMotionCapture].
     * Safe to call when not started. Always pair start/stop on
     * Activity onResume/onPause to avoid leaving the sensor active
     * after the user backgrounds the app.
     */
    fun stopMotionCapture() {
        MotionCollector.stop()
    }

    /**
     * Toggle contact-lock collection. When ON and the host has been
     * granted READ_CONTACTS, every register/verify ships a salted-hash
     * fingerprint of the user's phone contacts. Server returns a
     * [ContactsReport] with the overlap percentage vs the stored
     * baseline. Host app's policy decides what to do.
     *
     * Default: OFF. Idempotent.
     *
     * The SDK never asks for the permission itself — the host is expected
     * to use the standard Android runtime-permission flow before flipping
     * this on. If you flip it on without the permission, the SDK uploads
     * zero hashes and the feature degrades to a no-op.
     */
    fun setContactLockEnabled(enabled: Boolean) {
        contactLockEnabled = enabled
    }

    /** True iff [setContactLockEnabled] was called with true. */
    fun isContactLockEnabled(): Boolean = contactLockEnabled

    /** True iff the host process currently holds READ_CONTACTS. */
    fun hasContactsPermission(): Boolean {
        if (!isInitialized) return false
        return ContactsCollector.hasPermission(config.context)
    }

    /** Internal — collect the salted-hash contact set, or empty list if off. */
    internal fun collectContactHashes(): List<String> {
        if (!isInitialized || !contactLockEnabled) return emptyList()
        return ContactsCollector.collect(config.context, config.apiKey)
    }

    // ==================== Public Data Classes ====================
    
    enum class Status {
        TRUSTED,            // Device is trusted, allow access
        NEW_DEVICE,         // New device, needs approval from primary
        PENDING,            // Waiting for approval
        REJECTED,           // Device rejected (explicit user decision OR
                            //   off-network when same-network policy is on
                            //   — see VerificationResult.reason for the
                            //   specific cause: 'different_network' /
                            //   'rejected_by_user' / etc.)
        FEATURE_DISABLED,   // Server returned 403 — verifai-verification or
                            // -patterns is OFF on this API key. Surface a
                            // clean "ask your admin to enable" UI instead
                            // of treating it as a generic ERROR.
        ERROR               // Something went wrong
    }
    
    enum class TrustLevel {
        BASELINE,       // First login, score 50
        MEDIUM,         // 2-4 logins, score 70
        HIGH,           // 5-9 logins, score 85
        VERY_HIGH       // 10+ logins, score 95
    }
    
    enum class DeviceType {
        ANDROID,
        PC
    }
    
    data class Options(
        val enablePlayIntegrity: Boolean = true,
        val timeoutSeconds: Int = 30,
        /**
         * Override the API base URL. Default points at the production
         * 2stars cluster (https://api.2stars.io/verifai/v1). Set to
         * `https://api.staging.2stars.io/verifai/v1` for staging, or
         * `http://10.0.2.2:8080/api/v1/verifai` for an emulator hitting
         * a local docker compose stack (the local backend still mounts
         * the legacy `/api/v1/...` paths — the slash-star is spelled out
         * because Kotlin's block comments nest, and a literal `/` followed
         * by `*` inside this KDoc would open an inner comment that never
         * closes and silently swallow the rest of the file).
         */
        val baseUrl: String? = null,
    )
    
    data class RegistrationResult(
        val success: Boolean,
        val deviceId: String? = null,
        val error: String? = null,
        /** See [VerificationResult.behavioral]. */
        val behavioral: BehavioralReport? = null,
        /** See [VerificationResult.contacts]. */
        val contacts: ContactsReport? = null,
    )
    
    data class VerificationResult(
        val status: Status,
        val trustScore: Int = 0,
        val trustLevel: TrustLevel = TrustLevel.BASELINE,
        val deviceId: String? = null,
        val sessionId: String? = null,  // For NEW_DEVICE status
        val error: String? = null,
        /**
         * Outcome of the behavioral biometrics check, if the developer's
         * key has `verifai-behavioral` enabled. Null when the feature is
         * off, when the SDK didn't capture enough gestures to ship a
         * payload, or when the device hasn't yet received any baseline.
         *
         * Notable interactions with [status]:
         *   - When `verifai-behavioral-block` is ON and behavioral.status
         *     is MISMATCH, [status] is REJECTED with reason
         *     'behavioral_mismatch' (overrides the device-fingerprint
         *     verdict). Read [behavioral] to see why.
         *   - When `verifai-behavioral-block` is OFF, MISMATCH is
         *     informational — [status] reflects the fingerprint verdict
         *     (typically TRUSTED) and the host app can decide what to do
         *     with the soft signal.
         */
        val behavioral: BehavioralReport? = null,
        /**
         * Server-side pattern analysis outcome (3.1.0+). Surfaces the
         * anomalies the backend detected on top of the signal-hash
         * compare: re-registration cadence, multi-user device, long
         * absence, impossible travel. `null` when the server omits the
         * field (older backend, or feature not run for this call).
         */
        val patterns: PatternsReport? = null,
        /**
         * Strict-block mode state (3.1.0+). Non-null only when the
         * key has `verifai-strict-block` enabled. After 10 successful
         * verifies on the same device the mode flips from `TRAINING`
         * to `ARMED`, after which any anomaly (signal drift or
         * analyzePatterns flag) causes a REJECT with reason
         * `strict_block:...` instead of a trust-score demotion.
         */
        val strictMode: StrictModeReport? = null,
        /**
         * Advanced-patterns (day-of-week + hour-bucket) verdict (3.2.0+).
         * Non-null only when both the admin (`verifai-advanced-patterns`)
         * AND the developer (dashboard opt-in) have enabled the feature.
         */
        val advanced: AdvancedReport? = null,
        /**
         * Contact-lock verdict (3.2.0+). Non-null only when
         * `verifai-contact-lock` is enabled AND the SDK uploaded a
         * non-empty contact hash list this call (which requires the
         * host to have flipped [setContactLockEnabled] on and to hold
         * READ_CONTACTS).
         */
        val contacts: ContactsReport? = null,
        /**
         * 0–100 per-axis breakdown of the composite trust score (3.2.0+).
         * Keys present mirror which axes ran for this call: `device`,
         * `behavioral`, `advanced`, `patterns`, `contacts`. Always
         * present on a TRUSTED response; absent on REJECTED responses
         * from older servers.
         */
        val scoreBreakdown: Map<String, Int> = emptyMap(),
    )

    /**
     * Advanced-patterns outcome (3.2.0+).
     *
     * @property status `LEARNING` while the day/hour bucket has fewer
     *                  than the minimum number of prior samples to
     *                  compare against (default 3); `MATCH` when the
     *                  current login resembles enough of the bucket's
     *                  history; `MISMATCH` otherwise.
     * @property bucket the bucket key the server matched against, e.g.
     *                  `"Mon-9"` for Monday 09:00-10:59.
     * @property bucketSampleCount how many prior samples were in the bucket.
     * @property matchRatio 0.0–1.0, fraction of bucket samples that
     *                  strongly matched the current login. Only meaningful
     *                  when status != LEARNING.
     * @property threshold the bucket-match threshold from the server (0.5).
     */
    data class AdvancedReport(
        val status: AdvancedStatus,
        val bucket: String,
        val bucketSampleCount: Int = 0,
        val matchRatio: Double = 0.0,
        val threshold: Double = 0.5,
    )

    enum class AdvancedStatus { LEARNING, MATCH, MISMATCH }

    /**
     * Contact-lock outcome (3.2.0+).
     *
     * @property status `BASELINE` if this was the first scan and the
     *                  server just persisted the set; `MATCH` when
     *                  overlapPct >= configured threshold; `MISMATCH`
     *                  when below.
     * @property overlapPct 0–100, |intersect| / |stored|. Null on BASELINE.
     * @property storedCount how many hashes are on file.
     * @property incomingCount how many hashes we just uploaded.
     * @property threshold dev's configured threshold for MATCH/MISMATCH.
     */
    data class ContactsReport(
        val status: ContactsStatus,
        val overlapPct: Int? = null,
        val storedCount: Int = 0,
        val incomingCount: Int = 0,
        val intersectCount: Int = 0,
        val threshold: Int = 80,
    )

    enum class ContactsStatus { BASELINE, MATCH, MISMATCH }

    /**
     * Strict-block mode state from /verifyDevice.
     *
     * @property state TRAINING while loginCount < trainingTotal; ARMED
     *                 once the device has completed the training window
     *                 and the strict-block check is active.
     * @property loginCount    successful verifies on this device so far
     * @property trainingTotal threshold to flip TRAINING → ARMED (10)
     * @property remaining     trainingTotal - loginCount (clamped to 0)
     * @property triggered     list of anomaly tags that just caused a
     *                         REJECT, if any. Empty on a TRUSTED response.
     */
    data class StrictModeReport(
        val state: StrictModeState,
        val loginCount: Int = 0,
        val trainingTotal: Int = 10,
        val remaining: Int = 0,
        val triggered: List<String> = emptyList(),
    )

    enum class StrictModeState { TRAINING, ARMED }

    /**
     * Server-side pattern analysis outcome. Mirrors the JSON shape
     * returned by /verifyDevice's `patterns` field. The raw JSON is
     * also exposed (`rawJson`) so consumers can dig into the sub-results
     * (reRegistration, multiUserDevice, longAbsence, impossibleTravel)
     * without us having to mirror every server-side schema change.
     *
     * @property riskLevel "low" | "medium" | "high" | "critical"
     * @property trustDelta integer delta applied to the base trust
     *           score; always 0 or negative (patterns demote, never
     *           promote).
     * @property anomalies short tag strings describing each flagged
     *           detector — e.g. "impossible_travel:9560km_in_5min_114720kmh",
     *           "multi_user_device:3_users".
     * @property rawJson the unparsed JSON object, pretty-printed, for
     *           debug display in test harnesses. Null if the server
     *           omitted it.
     */
    data class PatternsReport(
        val riskLevel: String,
        val trustDelta: Int = 0,
        val anomalies: List<String> = emptyList(),
        val rawJson: String? = null,
    )

    /**
     * Behavioral biometrics outcome attached to [VerificationResult] and
     * [RegistrationResult] when the feature is on.
     *
     * @property status TRAINING during the first 5 logins (baseline still
     *                  building); MATCH after lock when the incoming
     *                  pattern falls into a recognised bucket; MISMATCH
     *                  when it doesn't.
     * @property loginCount how many training sessions have been recorded
     *                      against this device's locked baseline so far
     *                      (capped at 5). Useful for "Training: 3/5" UI.
     * @property remainingTraining sessions left before the baseline locks,
     *                             0 once locked.
     * @property mismatches list of category names that failed the bucket
     *                      check on a MISMATCH outcome ("swipeVelocity",
     *                      "tapPressure", "buttonRhythm"). Empty / null
     *                      otherwise.
     */
    data class BehavioralReport(
        val status: BehavioralStatus,
        val loginCount: Int = 0,
        val remainingTraining: Int = 0,
        val mismatches: List<String> = emptyList(),
    )

    enum class BehavioralStatus {
        TRAINING,
        MATCH,
        MISMATCH,
    }

    /**
     * Snapshot of an approval session as returned by [getSession] / [pollSession].
     *
     * @property status one of "pending", "approved", "rejected", "expired",
     *                  or the synthetic "timeout" from [pollSession].
     * @property approvedBy human label of who approved (only set when status="approved").
     * @property rejectionReason reason text the approver supplied (only on "rejected").
     */
    data class SessionState(
        val id:              String,
        val status:          String,
        val approvedBy:      String? = null,
        val rejectionReason: String? = null,
        val expiresAt:       Long    = 0L,
    )
    
    data class TrustScore(
        val level: TrustLevel,
        val score: Int,
        val loginCount: Int,
        val ageInDays: Int
    )
    
    data class Device(
        val id: String,
        val type: DeviceType,
        val name: String,
        val createdAt: Long,
        val lastUsed: Long?
    )
    
    data class ApprovalRequest(
        val sessionId: String,
        val type: DeviceType,
        val deviceInfo: String,
        val publicIP: String
    )

    /** Result of an OTP gate check. `allow=false` means block delivery. */
    data class OtpGateResult(
        val allow: Boolean,
        val reason: String,
        val trustScore: Int,
        val trustLevel: TrustLevel,
        val hint: String? = null
    )

    /** Result of a user or single-device reset. */
    data class ResetResult(
        val ok: Boolean,
        val devicesDeleted: Int,
        val sessionsDeleted: Int,
        val error: String? = null
    )
    
    internal data class Config(
        val context: Context,
        val apiKey: String,
        val options: Options
    )
}
