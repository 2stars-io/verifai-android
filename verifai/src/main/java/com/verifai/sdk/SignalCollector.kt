package com.verifai.sdk

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.util.*

/**
 * Internal signal collector - not exposed to SDK users
 */
internal object SignalCollector {
    
    private lateinit var appContext: Context
    private var deviceSalt: String? = null
    
    fun init(context: Context) {
        appContext = context.applicationContext
        
        // Get or create device salt (stored forever)
        val prefs = context.getSharedPreferences("verifai_internal", Context.MODE_PRIVATE)
        deviceSalt = prefs.getString("device_salt", null)
        if (deviceSalt == null) {
            deviceSalt = UUID.randomUUID().toString()
            prefs.edit().putString("device_salt", deviceSalt).apply()
        }
    }
    
    /**
     * Result of a signal-collection pass.
     *
     * @property hashes  the 12 hashed signal categories (sent in `signalHashes`)
     * @property playIntegrityToken the RAW token from the Play Integrity API
     *           (sent at the top level so the server can decode it). Hashing
     *           a token containing a server-generated nonce was useless for
     *           matching (different on every call) — we now send the raw
     *           token and the server's stores the decoded verdict.
     */
    data class CollectedSignals(
        val hashes: Map<String, String>,
        val playIntegrityToken: String,
    )

    /**
     * Collect signals + the raw Play Integrity token. Raw signal values
     * (device id, timezone, etc.) never leave this function — only their
     * hashes go to the network. The Play Integrity token IS sent raw,
     * because only Google can decode it and we (and the server) need
     * Google's verdict.
     */
    suspend fun collect(cloudProjectNumber: Long): CollectedSignals = withContext(Dispatchers.IO) {
        val salt = deviceSalt ?: UUID.randomUUID().toString()
        val androidId = Settings.Secure.getString(appContext.contentResolver, Settings.Secure.ANDROID_ID) ?: ""

        val device = collectDevice()
        val telephony = collectTelephony()
        val keyboards = collectKeyboards()
        val integrity = collectIntegrity()
        val defaultApps = collectDefaultApps()
        val personalization = collectPersonalization()
        val network = collectNetworkClass()

        val playIntegrityToken = try {
            getPlayIntegrityToken(cloudProjectNumber)
        } catch (e: Exception) {
            ""
        }

        val hashes = mapOf(
            "androidIdHash"       to hash(salt, androidId),
            // Legacy field — still emitted for backward compatibility with
            // pre-3.0 servers, but the v3 server ignores it (the raw token
            // is what matters). Safe to remove once all backends are v3+.
            "playIntegrityHash"   to hash(salt, playIntegrityToken),
            "deviceHash"          to hash(salt, device["manufacturer"], device["model"], device["brand"], device["fingerprint"], device["screenWidth"], device["screenHeight"]),
            "localeHash"          to hash(salt, device["timezone"], device["language"], device["country"]),
            "carrierHash"         to hash(salt, telephony["simCountry"], telephony["carrierName"]),
            "keyboardHash"        to hash(salt, keyboards["keyboardList"]),
            "integrityHash"       to hash(salt, integrity["isEmulator"], integrity["isRooted"]),
            // Removed: appsHash (was a count of getInstalledApplications, which
            // on Android 11+ returns only the host app + system apps unless
            // QUERY_ALL_PACKAGES is granted — Play-restricted. Signal degrades
            // to essentially constant on modern devices, so it added noise
            // without discrimination. Dropped 3.1.0.
            "defaultAppsHash"     to hash(salt, defaultApps["defaultBrowser"]),
            "personalizationHash" to hash(salt, personalization["ringtoneName"], personalization["darkMode"]),
            // networkClassHash replaces the old networkHash (which only hashed
            // whether WiFi was *enabled* — not the active transport). New
            // signal categorises the active connection as wifi/cellular/
            // ethernet/other, plus a vpn flag derived from
            // NetworkCapabilities.TRANSPORT_VPN. Useful because:
            //   - "home WiFi" vs "cellular" is a strong per-user habit signal
            //   - VPN flag flips when the user adds/removes a VPN, which is
            //     itself meaningful (legit users rarely flip mid-session)
            // Tor exit detection stays server-side (IP reputation).
            "networkClassHash"    to hash(salt, network["transport"], network["isVpn"]),
            "usageHash"           to hash(salt, device["uptimeHours"]),
        )

        CollectedSignals(hashes = hashes, playIntegrityToken = playIntegrityToken)
    }

    /**
     * Backward-compat: hash-only API for code that doesn't yet need the
     * raw Play Integrity token. New code should use `collect()` and pass
     * `playIntegrityToken` to the server.
     */
    @Deprecated(
        message = "Use collect() to get the raw Play Integrity token alongside the hashes.",
        replaceWith = ReplaceWith("collect(cloudProjectNumber).hashes"),
    )
    suspend fun collectSignalHashes(cloudProjectNumber: Long): Map<String, String> =
        collect(cloudProjectNumber).hashes
    
    /**
     * Get unique device identifier hash
     */
    fun getDeviceIdHash(): String {
        val androidId = Settings.Secure.getString(appContext.contentResolver, Settings.Secure.ANDROID_ID) ?: ""
        return hash(deviceSalt ?: "", androidId, Build.MODEL, Build.BRAND)
    }
    
    private fun collectDevice(): Map<String, String> = mapOf(
        "manufacturer" to Build.MANUFACTURER,
        "model" to Build.MODEL,
        "brand" to Build.BRAND,
        "fingerprint" to Build.FINGERPRINT,
        "screenWidth" to appContext.resources.displayMetrics.widthPixels.toString(),
        "screenHeight" to appContext.resources.displayMetrics.heightPixels.toString(),
        "timezone" to TimeZone.getDefault().id,
        "language" to Locale.getDefault().language,
        "country" to Locale.getDefault().country,
        "uptimeHours" to (android.os.SystemClock.elapsedRealtime() / 3600000).toString()
    )
    
    private fun collectTelephony(): Map<String, String> {
        return try {
            val tm = appContext.getSystemService(Context.TELEPHONY_SERVICE) as android.telephony.TelephonyManager
            mapOf(
                "carrierName" to (tm.networkOperatorName ?: ""),
                "simCountry" to (tm.simCountryIso?.uppercase() ?: "")
            )
        } catch (e: Exception) {
            emptyMap()
        }
    }
    
    private fun collectKeyboards(): Map<String, String> {
        return try {
            val imm = appContext.getSystemService(Context.INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager
            val keyboards = imm.enabledInputMethodList
            val keyboardNames = keyboards.map { it.loadLabel(appContext.packageManager).toString() }.sorted()
            mapOf("keyboardList" to keyboardNames.joinToString(","))
        } catch (e: Exception) {
            emptyMap()
        }
    }
    
    private fun collectIntegrity(): Map<String, String> {
        val isEmulator = Build.FINGERPRINT.contains("generic") ||
                Build.MODEL.contains("Emulator") ||
                Build.MODEL.contains("Android SDK") ||
                Build.MANUFACTURER.contains("Genymotion")
        
        val isRooted = listOf("/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su")
            .any { java.io.File(it).exists() }
        
        return mapOf(
            "isEmulator" to isEmulator.toString(),
            "isRooted" to isRooted.toString()
        )
    }
    
    private fun collectDefaultApps(): Map<String, String> {
        return try {
            val pm = appContext.packageManager
            val browserIntent = android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse("http://"))
            val browserResolve = pm.resolveActivity(browserIntent, PackageManager.MATCH_DEFAULT_ONLY)
            val browser = browserResolve?.activityInfo?.let { pm.getApplicationLabel(it.applicationInfo).toString() } ?: ""
            mapOf("defaultBrowser" to browser)
        } catch (e: Exception) {
            emptyMap()
        }
    }
    
    private fun collectPersonalization(): Map<String, String> {
        val darkMode = try {
            val nightMode = appContext.resources.configuration.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK
            (nightMode == android.content.res.Configuration.UI_MODE_NIGHT_YES).toString()
        } catch (e: Exception) { "false" }
        
        val ringtoneName = try {
            val ringtoneUri = android.media.RingtoneManager.getActualDefaultRingtoneUri(appContext, android.media.RingtoneManager.TYPE_RINGTONE)
            val ringtone = android.media.RingtoneManager.getRingtone(appContext, ringtoneUri)
            ringtone?.getTitle(appContext) ?: "Default"
        } catch (e: Exception) { "Default" }
        
        return mapOf(
            "darkMode" to darkMode,
            "ringtoneName" to ringtoneName
        )
    }
    
    /**
     * Classify the *active* network connection rather than just "is WiFi
     * enabled". Uses NetworkCapabilities (API 23+), which gives us:
     *  - the active transport (wifi / cellular / ethernet / bluetooth / vpn / other)
     *  - a separate VPN flag (a connection can be cellular+VPN, wifi+VPN, etc.)
     *
     * Permission: requires ACCESS_NETWORK_STATE only, which the SDK manifest
     * already declares. No runtime prompt.
     */
    private fun collectNetworkClass(): Map<String, String> {
        return try {
            val cm = appContext.getSystemService(Context.CONNECTIVITY_SERVICE)
                as android.net.ConnectivityManager
            val active = cm.activeNetwork ?: return mapOf("transport" to "none", "isVpn" to "false")
            val caps = cm.getNetworkCapabilities(active)
                ?: return mapOf("transport" to "unknown", "isVpn" to "false")

            val transport = when {
                caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI)      -> "wifi"
                caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)  -> "cellular"
                caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET)  -> "ethernet"
                caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_BLUETOOTH) -> "bluetooth"
                else -> "other"
            }
            // VPN is a separate transport flag — a VPN tunnel sits on top of
            // wifi/cellular, so we report both. Negating NOT_VPN is the
            // canonical check (TRANSPORT_VPN alone misses some configurations).
            val isVpn = !caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            mapOf("transport" to transport, "isVpn" to isVpn.toString())
        } catch (e: Exception) {
            mapOf("transport" to "error", "isVpn" to "false")
        }
    }
    
    private suspend fun getPlayIntegrityToken(cloudProjectNumber: Long): String {
        val integrityManager = IntegrityManagerFactory.create(appContext)
        val nonce = UUID.randomUUID().toString()
        
        val request = IntegrityTokenRequest.builder()
            .setCloudProjectNumber(cloudProjectNumber)
            .setNonce(nonce)
            .build()
        
        val response = integrityManager.requestIntegrityToken(request).await()
        return response.token()
    }
    
    private fun hash(vararg inputs: String?): String {
        val combined = inputs.filterNotNull().joinToString("|")
        val bytes = MessageDigest.getInstance("SHA-256").digest(combined.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
