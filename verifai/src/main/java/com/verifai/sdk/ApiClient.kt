package com.verifai.sdk

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Internal API client - handles all HTTP requests to VerifAI backend
 */
internal object ApiClient {
    
    // v3.0.0 — VerifAI lives inside the unified 2stars platform. The
    // legacy Cloud Functions backend is deprecated; all calls go to the
    // platform's per-product routing scheme:
    //   https://api.2stars.io/verifai/v1/...
    //
    // The same `hbs_live_` key that authenticates against /video/v1/*
    // (the Video AI surface) authenticates here too.
    //
    // Override at runtime via `VerifAI.Options(baseUrl = "...")` when
    // running against staging, a local docker stack, or a self-hosted
    // deployment that hasn't migrated to the per-product paths yet.
    private const val DEFAULT_BASE_URL = "https://api.2stars.io/verifai/v1"

    private fun baseUrl(config: VerifAI.Config): String = config.options.baseUrl ?: DEFAULT_BASE_URL
    
    suspend fun registerToken(config: VerifAI.Config, userId: String, fcmToken: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val deviceIdHash = SignalCollector.getDeviceIdHash()
            val body = JSONObject().apply {
                put("userId", userId)
                put("fcmToken", fcmToken)
                put("deviceId", deviceIdHash)
            }

            val response = post(config, "/registerToken", body)
            response.optBoolean("success", false)
        } catch (e: Exception) {
            false
        }
    }
    
    suspend fun listDevices(config: VerifAI.Config, userId: String): List<VerifAI.Device> = withContext(Dispatchers.IO) {
        try {
            val response = get(config, "/listDevices?userId=${userId.encodeUrl()}")
            val devices = mutableListOf<VerifAI.Device>()
            
            val devicesArray = response.optJSONArray("devices")
            if (devicesArray != null) {
                for (i in 0 until devicesArray.length()) {
                    val d = devicesArray.getJSONObject(i)
                    devices.add(VerifAI.Device(
                        id = d.optString("id"),
                        type = if (d.optString("type") == "pc") VerifAI.DeviceType.PC else VerifAI.DeviceType.ANDROID,
                        name = d.optString("browser", d.optString("platform", "Unknown")),
                        createdAt = d.optLong("createdAt", 0),
                        lastUsed = if (d.has("lastLogin")) d.optLong("lastLogin") else null
                    ))
                }
            }
            
            devices
        } catch (e: Exception) {
            emptyList()
        }
    }
    
    suspend fun deleteDevice(config: VerifAI.Config, deviceId: String, type: VerifAI.DeviceType): Boolean = withContext(Dispatchers.IO) {
        try {
            val typeStr = if (type == VerifAI.DeviceType.PC) "pc" else "android"
            val response = delete(config, "/deleteDevice?deviceId=${deviceId.encodeUrl()}&type=$typeStr")
            response.optBoolean("success", false)
        } catch (e: Exception) {
            false
        }
    }
    
    suspend fun getTrustScore(config: VerifAI.Config, deviceId: String, type: VerifAI.DeviceType): VerifAI.TrustScore? = withContext(Dispatchers.IO) {
        try {
            val typeStr = when (type) {
                VerifAI.DeviceType.PC -> "pc"
                VerifAI.DeviceType.ANDROID -> "android"
            }
            val response = get(config, "/getTrustScore?deviceId=${deviceId.encodeUrl()}&type=$typeStr")
            
            val level = when (response.optString("trustLevel")) {
                "very_high" -> VerifAI.TrustLevel.VERY_HIGH
                "high" -> VerifAI.TrustLevel.HIGH
                "medium" -> VerifAI.TrustLevel.MEDIUM
                else -> VerifAI.TrustLevel.BASELINE
            }
            
            VerifAI.TrustScore(
                level = level,
                score = response.optInt("trustScore", 50),
                loginCount = response.optInt("loginCount", 0),
                ageInDays = response.optInt("ageInDays", 0)
            )
        } catch (e: Exception) {
            null
        }
    }
    
    suspend fun approveDevice(config: VerifAI.Config, sessionId: String, type: VerifAI.DeviceType): Boolean = withContext(Dispatchers.IO) {
        try {
            val body = JSONObject().apply {
                put("sessionId", sessionId)
                put("type", if (type == VerifAI.DeviceType.PC) "pc" else "android")
                put("approvedBy", "VerifAI SDK")
            }
            
            val response = post(config, "/approveDevice", body)
            response.optBoolean("success", false)
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Fetch the current state of an approval session. Used by the
     * new-device side to wait for a trusted device to approve.
     * Returns null on transport / decode error so callers can poll-retry.
     */
    suspend fun getSession(config: VerifAI.Config, sessionId: String): VerifAI.SessionState? = withContext(Dispatchers.IO) {
        try {
            val response = get(config, "/getSession?sessionId=${sessionId.encodeUrl()}")
            val status = response.optString("status", "")
            if (status.isBlank()) return@withContext null
            VerifAI.SessionState(
                id              = response.optString("id", sessionId),
                status          = status,
                approvedBy      = response.optString("approvedBy", null),
                rejectionReason = response.optString("rejectionReason", null),
                expiresAt       = response.optLong("expiresAt", 0L),
            )
        } catch (e: Exception) {
            null
        }
    }

    suspend fun rejectDevice(config: VerifAI.Config, sessionId: String, type: VerifAI.DeviceType, reason: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val body = JSONObject().apply {
                put("sessionId", sessionId)
                put("type", if (type == VerifAI.DeviceType.PC) "pc" else "android")
                put("reason", reason)
            }
            
            val response = post(config, "/rejectDevice", body)
            response.optBoolean("success", false)
        } catch (e: Exception) {
            false
        }
    }
    
    // ==================== HTTP Helpers ====================
    
    /**
     * Thrown when the server reports the requested feature is disabled
     * for this API key (HTTP 403 with code=feature_disabled). Surfaced
     * to callers as Status.FEATURE_DISABLED so the app can show a clean
     * "your account doesn't have VerifAI verification enabled — contact
     * support" path instead of a generic ERROR.
     */
    class FeatureDisabledException(val featureName: String, message: String) : RuntimeException(message)

    internal fun get(config: VerifAI.Config, endpoint: String): JSONObject {
        return execute(config, endpoint, "GET", null)
    }

    internal fun post(config: VerifAI.Config, endpoint: String, body: JSONObject): JSONObject {
        return execute(config, endpoint, "POST", body)
    }

    internal fun delete(config: VerifAI.Config, endpoint: String): JSONObject {
        return execute(config, endpoint, "DELETE", null)
    }

    /**
     * Single execute path so Authorization, timeouts, and error handling
     * stay consistent across verbs. Throws [FeatureDisabledException]
     * when the server returns 403 with code=feature_disabled.
     */
    private fun execute(config: VerifAI.Config, endpoint: String, method: String, body: JSONObject?): JSONObject {
        val url = URL("${baseUrl(config)}$endpoint")
        val conn = url.openConnection() as HttpURLConnection

        conn.requestMethod = method
        conn.setRequestProperty("Authorization", "Bearer ${config.apiKey}")
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("Accept", "application/json")
        conn.setRequestProperty("User-Agent", "VerifAI-Android/${VerifAI.SDK_VERSION}")
        conn.connectTimeout = config.options.timeoutSeconds * 1000
        conn.readTimeout = config.options.timeoutSeconds * 1000

        if (body != null) {
            conn.doOutput = true
            conn.outputStream.bufferedWriter().use { it.write(body.toString()) }
        }

        val code = conn.responseCode
        val stream = if (code in 200..299) conn.inputStream else conn.errorStream
        val text = stream?.bufferedReader()?.readText() ?: ""

        if (code in 200..299) {
            return JSONObject(text.ifBlank { "{}" })
        }
        // Translate the structured 403 into a typed exception. The 2stars
        // server returns { "error": { "code": "feature_disabled", "message": "..." } }.
        if (code == 403) {
            try {
                val err = JSONObject(text).optJSONObject("error")
                if (err != null && err.optString("code") == "feature_disabled") {
                    throw FeatureDisabledException(
                        endpoint.removePrefix("/"),
                        err.optString("message", "Feature disabled"),
                    )
                }
            } catch (_: org.json.JSONException) { /* fall through */ }
        }
        throw RuntimeException("VerifAI HTTP $code: ${text.take(200)}")
    }

    private fun String.encodeUrl(): String = java.net.URLEncoder.encode(this, "UTF-8")
}
