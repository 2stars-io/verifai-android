package com.verifai.sdk

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.Mac

/**
 * Per-device salt source for SignalCollector.
 *
 * Why this exists: the legacy implementation kept the salt in a plain
 * SharedPreferences slot, which is wiped by `pm clear`, by "Clear app data"
 * in system settings, and by any app data restore that doesn't include
 * sharedpref files. When the salt rotates the device fingerprint changes
 * → the server treats the same physical device as a brand-new device →
 * the user gets a cross-device approval prompt that no one can fulfil on
 * single-device accounts (the 2026-05-29 incident).
 *
 * Strategy:
 *   1. Legacy fast-path. If a prior install left a salt in the old
 *      SharedPreferences slot, keep using it — switching mid-install
 *      would itself change the hash and trip the rescue flow needlessly.
 *   2. Otherwise derive a salt from an AndroidKeyStore HMAC-SHA-256 key.
 *      The key itself never leaves the keystore; we compute
 *      HMAC(label) → 64 hex chars. Keystore entries on API 28+ survive
 *      `pm clear` (they live outside the app data directory and are
 *      only freed when the UID is freed — i.e. uninstall). Same key
 *      → same HMAC → same salt → same fingerprint → same device row.
 *   3. Last-resort fallback. On the rare device where the AndroidKeyStore
 *      provider can't be initialised, generate a UUID and stash it in
 *      the legacy SharedPreferences slot.
 *
 * Paired with the server's verifai-behavioral-rescue path: even on devices
 * where the keystore DOES get wiped (some pre-Android-9 OEM builds), the
 * server will silently migrate the row to the new hash on the first verify
 * whose behavioral signature matches the prior baseline.
 */
internal object DeviceSaltStore {

    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS         = "verifai_device_salt_kek_v1"
    private const val SALT_LABEL        = "verifai_device_salt"
    private const val LEGACY_PREFS      = "verifai_internal"
    private const val LEGACY_KEY        = "device_salt"

    fun get(context: Context): String {
        val legacy = context
            .getSharedPreferences(LEGACY_PREFS, Context.MODE_PRIVATE)
            .getString(LEGACY_KEY, null)
        if (!legacy.isNullOrEmpty()) return legacy

        return try {
            keystoreDerivedSalt()
        } catch (_: Exception) {
            val fresh = UUID.randomUUID().toString()
            context.getSharedPreferences(LEGACY_PREFS, Context.MODE_PRIVATE)
                .edit().putString(LEGACY_KEY, fresh).apply()
            fresh
        }
    }

    private fun keystoreDerivedSalt(): String {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (!ks.containsAlias(KEY_ALIAS)) {
            val spec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN,
            ).build()
            val gen = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_HMAC_SHA256,
                KEYSTORE_PROVIDER,
            )
            gen.init(spec)
            gen.generateKey()
        }
        val key = ks.getKey(KEY_ALIAS, null)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(key)
        return mac.doFinal(SALT_LABEL.toByteArray()).joinToString("") { "%02x".format(it) }
    }
}
