package com.verifai.sdk

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.security.MessageDigest

/**
 * Internal device manager - handles registration and verification flow.
 * All operations go through the REST API (ApiClient) — no direct Firestore access.
 */
internal object DeviceManager {
    
    private const val CLOUD_PROJECT_NUMBER = 71845524469L

    /**
     * Read the host app's package + version (its OWN package — no
     * permission needed). Returns triple of (packageName, versionName,
     * versionCode). Sent on every register/verify so the server can detect
     * version drift (user normally on v2.3, attempt arrives from v1.0 →
     * rollback or cloned APK signal).
     */
    private fun collectHostAppVersion(context: android.content.Context): Triple<String, String, Long> {
        return try {
            val info = context.packageManager.getPackageInfo(context.packageName, 0)
            val name = info.versionName ?: ""
            val code = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                info.longVersionCode
            } else {
                @Suppress("DEPRECATION")
                info.versionCode.toLong()
            }
            Triple(context.packageName, name, code)
        } catch (e: Exception) {
            Triple(context.packageName ?: "", "", 0L)
        }
    }

    private fun JSONObject.attachVersionMetadata(context: android.content.Context) {
        val (pkg, ver, code) = collectHostAppVersion(context)
        // SDK_VERSION baked in by buildConfigField. If the consumer is on
        // an old SDK that doesn't have BuildConfig.SDK_VERSION, the field
        // is absent at compile time so the value would be a literal "3.1.0"
        // for this build; older builds simply won't send the field.
        put("sdkVersion", BuildConfig.SDK_VERSION)
        put("hostPackageName", pkg)
        put("hostAppVersion", ver)
        put("hostAppVersionCode", code)
    }

    /**
     * Register device - collects signal hashes and sends to API
     */
    suspend fun register(config: VerifAI.Config, userId: String): VerifAI.RegistrationResult = withContext(Dispatchers.IO) {
        try {
            val collected = SignalCollector.collect(CLOUD_PROJECT_NUMBER)
            val deviceIdHash = SignalCollector.getDeviceIdHash()
            val behavioralHashes = BehavioralCollector.getBehavioralHashes()

            val contactHashes = VerifAI.collectContactHashes()
            val body = JSONObject().apply {
                put("userId", userId)
                put("deviceIdHash", deviceIdHash)
                put("signalHashes", JSONObject(collected.hashes))
                if (collected.playIntegrityToken.isNotEmpty()) {
                    put("playIntegrityToken", collected.playIntegrityToken)
                }
                put("deviceType", "android")
                put("deviceModel", android.os.Build.MODEL)
                put("deviceBrand", android.os.Build.BRAND)
                attachVersionMetadata(config.context)
                if (behavioralHashes.isNotEmpty()) {
                    put("behavioralHashes", JSONObject(behavioralHashes))
                }
                if (contactHashes.isNotEmpty()) {
                    put("contactHashes", org.json.JSONArray(contactHashes))
                }
            }

            val response = ApiClient.post(config, "/registerDevice", body)
            val success = response.optBoolean("success", false)
            val deviceId = response.optString("deviceId", deviceIdHash.take(16))

            if (success) {
                // Store locally
                val prefs = config.context.getSharedPreferences("verifai_device", android.content.Context.MODE_PRIVATE)
                prefs.edit()
                    .putString("certificate", response.optString("masterHash", ""))
                    .putString("device_id", deviceId)
                    .putInt("login_count", 1)
                    .putLong("first_login", System.currentTimeMillis())
                    .apply()
                // Drop the captured behavioral session — the next register/verify
                // should average over the next session, not the lifetime sum.
                BehavioralCollector.resetSession()
            }

            VerifAI.RegistrationResult(
                success = success,
                deviceId = deviceId,
                error = if (!success) response.optString("error", "Registration failed") else null,
                behavioral = parseBehavioralReport(response.optJSONObject("behavioral")),
                contacts = parseContactsReport(response.optJSONObject("contacts")),
            )

        } catch (e: ApiClient.FeatureDisabledException) {
            VerifAI.RegistrationResult(
                success = false,
                error = "feature_disabled:${e.featureName}"
            )
        } catch (e: Exception) {
            VerifAI.RegistrationResult(
                success = false,
                error = e.message
            )
        }
    }
    
    /**
     * Verify device - sends signal hashes to API for comparison
     */
    suspend fun verify(config: VerifAI.Config, userId: String): VerifAI.VerificationResult = withContext(Dispatchers.IO) {
        try {
            val collected = SignalCollector.collect(CLOUD_PROJECT_NUMBER)
            val deviceIdHash = SignalCollector.getDeviceIdHash()
            val publicIP = NetworkUtils.getPublicIP()
            val behavioralHashes = BehavioralCollector.getBehavioralHashes()

            val contactHashes = VerifAI.collectContactHashes()
            val body = JSONObject().apply {
                put("userId", userId)
                put("deviceIdHash", deviceIdHash)
                put("signalHashes", JSONObject(collected.hashes))
                if (collected.playIntegrityToken.isNotEmpty()) {
                    put("playIntegrityToken", collected.playIntegrityToken)
                }
                put("deviceType", "android")
                put("publicIP", publicIP)
                put("deviceModel", android.os.Build.MODEL)
                put("deviceBrand", android.os.Build.BRAND)
                attachVersionMetadata(config.context)
                if (behavioralHashes.isNotEmpty()) {
                    put("behavioralHashes", JSONObject(behavioralHashes))
                }
                if (contactHashes.isNotEmpty()) {
                    put("contactHashes", org.json.JSONArray(contactHashes))
                }
            }

            val response = ApiClient.post(config, "/verifyDevice", body)
            val status = response.optString("status", "ERROR")

            val verifaiStatus = when (status) {
                "TRUSTED" -> VerifAI.Status.TRUSTED
                "NEW_DEVICE" -> VerifAI.Status.NEW_DEVICE
                "PENDING" -> VerifAI.Status.PENDING
                "REJECTED" -> VerifAI.Status.REJECTED
                else -> VerifAI.Status.ERROR
            }

            val trustLevelStr = response.optString("trustLevel", "BASELINE")
            val trustLevel = when (trustLevelStr) {
                "VERY_HIGH" -> VerifAI.TrustLevel.VERY_HIGH
                "HIGH" -> VerifAI.TrustLevel.HIGH
                "MEDIUM" -> VerifAI.TrustLevel.MEDIUM
                else -> VerifAI.TrustLevel.BASELINE
            }

            // Update local storage on trusted
            if (verifaiStatus == VerifAI.Status.TRUSTED) {
                val prefs = config.context.getSharedPreferences("verifai_device", android.content.Context.MODE_PRIVATE)
                val count = prefs.getInt("login_count", 0) + 1
                prefs.edit()
                    .putString("device_id", response.optString("deviceId", deviceIdHash.take(16)))
                    .putInt("login_count", count)
                    .putLong("last_login", System.currentTimeMillis())
                    .apply()
            }
            // Reset on every completed verify (whether TRUSTED or REJECTED).
            // The session window is "since the last verify call", regardless
            // of outcome — otherwise a rejected attempt would carry its
            // gestures into the next attempt's average and skew it.
            BehavioralCollector.resetSession()

            VerifAI.VerificationResult(
                status = verifaiStatus,
                trustScore = response.optInt("trustScore", 0),
                trustLevel = trustLevel,
                deviceId = response.optString("deviceId", deviceIdHash.take(16)),
                sessionId = response.optString("sessionId", null),
                error = response.optString("error", null),
                behavioral = parseBehavioralReport(response.optJSONObject("behavioral")),
                patterns = parsePatternsReport(response.optJSONObject("patterns")),
                strictMode = parseStrictModeReport(response.optJSONObject("strictMode")),
                advanced = parseAdvancedReport(response.optJSONObject("advanced")),
                contacts = parseContactsReport(response.optJSONObject("contacts")),
                scoreBreakdown = parseScoreBreakdown(response.optJSONObject("scoreBreakdown")),
            )

        } catch (e: ApiClient.FeatureDisabledException) {
            // Server says verifai-verification (or verifai-patterns) is OFF
            // for this API key. Surface a typed status so the host app can
            // route users to "enable VerifAI in your dashboard" rather than
            // showing a generic error.
            VerifAI.VerificationResult(
                status = VerifAI.Status.FEATURE_DISABLED,
                error = e.message
            )
        } catch (e: Exception) {
            VerifAI.VerificationResult(
                status = VerifAI.Status.ERROR,
                error = e.message
            )
        }
    }
    
    /**
     * Get trust score - now via REST API
     */
    suspend fun getTrustScore(config: VerifAI.Config, userId: String): VerifAI.TrustScore = withContext(Dispatchers.IO) {
        try {
            val deviceIdHash = SignalCollector.getDeviceIdHash().take(16)
            val response = ApiClient.get(config, "/getTrustScore?userId=${userId.encodeUrl()}&deviceId=${deviceIdHash.encodeUrl()}&type=android")
            
            val level = when (response.optString("level", response.optString("trustLevel", "BASELINE"))) {
                "VERY_HIGH", "very_high" -> VerifAI.TrustLevel.VERY_HIGH
                "HIGH", "high" -> VerifAI.TrustLevel.HIGH
                "MEDIUM", "medium" -> VerifAI.TrustLevel.MEDIUM
                else -> VerifAI.TrustLevel.BASELINE
            }
            
            VerifAI.TrustScore(
                level = level,
                score = response.optInt("score", response.optInt("trustScore", 0)),
                loginCount = response.optInt("loginCount", 0),
                ageInDays = response.optInt("ageInDays", 0)
            )
        } catch (e: Exception) {
            VerifAI.TrustScore(VerifAI.TrustLevel.BASELINE, 0, 0, 0)
        }
    }
    
    private fun String.encodeUrl(): String = java.net.URLEncoder.encode(this, "UTF-8")

    /**
     * Parse the optional `behavioral` object from a register/verify response
     * into the public [VerifAI.BehavioralReport]. Returns null when the
     * field is absent (the developer's key has verifai-behavioral OFF).
     *
     * Wire shape (server side: src/api/verifai.js):
     *   {
     *     "status": "training" | "match" | "mismatch",
     *     "loginCount": number,                 // training sessions recorded so far
     *     "remainingTraining": number,          // 0 once locked
     *     "mismatches": ["swipeVelocity", ...]  // present only on mismatch
     *   }
     */
    private fun parseBehavioralReport(json: org.json.JSONObject?): VerifAI.BehavioralReport? {
        if (json == null) return null
        val statusStr = json.optString("status", "")
        val status = when (statusStr) {
            "training" -> VerifAI.BehavioralStatus.TRAINING
            "match"    -> VerifAI.BehavioralStatus.MATCH
            "mismatch" -> VerifAI.BehavioralStatus.MISMATCH
            else -> return null
        }
        val mismatches = mutableListOf<String>()
        json.optJSONArray("mismatches")?.let { arr ->
            for (i in 0 until arr.length()) mismatches += arr.optString(i)
        }
        return VerifAI.BehavioralReport(
            status = status,
            loginCount = json.optInt("loginCount", 0),
            remainingTraining = json.optInt("remainingTraining", 0),
            mismatches = mismatches,
        )
    }

    /**
     * Parse the optional `patterns` object (server 3.1.0+) into a
     * [VerifAI.PatternsReport]. Returns null when the field is absent.
     *
     * Wire shape (src/api/verifai.js → src/api/helpers/verifaiPatterns.js):
     *   {
     *     "riskLevel": "low" | "medium" | "high" | "critical",
     *     "trustDelta": <-20..0 integer>,
     *     "anomalies": ["re_registration_cadence:5_in_24h", ...],
     *     "reRegistration": {...},
     *     "multiUserDevice": {...},
     *     "longAbsence": {...},
     *     "impossibleTravel": {...}
     *   }
     */
    private fun parsePatternsReport(json: org.json.JSONObject?): VerifAI.PatternsReport? {
        if (json == null) return null
        val anomalies = mutableListOf<String>()
        json.optJSONArray("anomalies")?.let { arr ->
            for (i in 0 until arr.length()) anomalies += arr.optString(i)
        }
        // Pretty-print the raw JSON for debug display. indent=2 is
        // readable and stays compact enough to fit a test-bench log.
        val raw = try { json.toString(2) } catch (e: Exception) { json.toString() }
        return VerifAI.PatternsReport(
            riskLevel = json.optString("riskLevel", "unknown"),
            trustDelta = json.optInt("trustDelta", 0),
            anomalies = anomalies,
            rawJson = raw,
        )
    }

    /**
     * Parse the optional `strictMode` object into [VerifAI.StrictModeReport].
     * Wire shape (src/api/verifai.js — verifai-strict-block branch):
     *   {
     *     "state": "training" | "armed",
     *     "loginCount": <int>,
     *     "trainingTotal": <int, default 10>,
     *     "remaining": <int>,
     *     "triggered": ["signal_drift:3_categories", "impossible_travel:...", ...]
     *   }
     */
    private fun parseStrictModeReport(json: org.json.JSONObject?): VerifAI.StrictModeReport? {
        if (json == null) return null
        val state = when (json.optString("state", "")) {
            "armed"    -> VerifAI.StrictModeState.ARMED
            "training" -> VerifAI.StrictModeState.TRAINING
            else       -> return null
        }
        val triggered = mutableListOf<String>()
        json.optJSONArray("triggered")?.let { arr ->
            for (i in 0 until arr.length()) triggered += arr.optString(i)
        }
        return VerifAI.StrictModeReport(
            state = state,
            loginCount = json.optInt("loginCount", 0),
            trainingTotal = json.optInt("trainingTotal", 10),
            remaining = json.optInt("remaining", 0),
            triggered = triggered,
        )
    }

    /**
     * Parse the optional `advanced` object (server 3.2.0+) into an
     * [VerifAI.AdvancedReport]. Returns null when the field is absent
     * or carries an unknown status.
     */
    private fun parseAdvancedReport(json: org.json.JSONObject?): VerifAI.AdvancedReport? {
        if (json == null) return null
        val status = when (json.optString("status", "")) {
            "learning" -> VerifAI.AdvancedStatus.LEARNING
            "match"    -> VerifAI.AdvancedStatus.MATCH
            "mismatch" -> VerifAI.AdvancedStatus.MISMATCH
            else       -> return null
        }
        return VerifAI.AdvancedReport(
            status = status,
            bucket = json.optString("bucket", ""),
            bucketSampleCount = json.optInt("bucketSampleCount", 0),
            matchRatio = json.optDouble("matchRatio", 0.0),
            threshold = json.optDouble("threshold", 0.5),
        )
    }

    /**
     * Parse the optional `contacts` object (server 3.2.0+) into a
     * [VerifAI.ContactsReport].
     */
    private fun parseContactsReport(json: org.json.JSONObject?): VerifAI.ContactsReport? {
        if (json == null) return null
        val status = when (json.optString("status", "")) {
            "baseline" -> VerifAI.ContactsStatus.BASELINE
            "match"    -> VerifAI.ContactsStatus.MATCH
            "mismatch" -> VerifAI.ContactsStatus.MISMATCH
            else       -> return null
        }
        val overlap = if (json.has("overlapPct") && !json.isNull("overlapPct")) {
            json.optInt("overlapPct", 0)
        } else null
        return VerifAI.ContactsReport(
            status = status,
            overlapPct = overlap,
            storedCount = json.optInt("storedCount", 0),
            incomingCount = json.optInt("incomingCount", 0),
            intersectCount = json.optInt("intersectCount", 0),
            threshold = json.optInt("threshold", 80),
        )
    }

    private fun parseScoreBreakdown(json: org.json.JSONObject?): Map<String, Int> {
        if (json == null) return emptyMap()
        val out = mutableMapOf<String, Int>()
        val keys = json.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            if (!json.isNull(k)) out[k] = json.optInt(k, 0)
        }
        return out
    }
}
