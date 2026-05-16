package com.verifai.sdk

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.ContactsContract
import androidx.core.content.ContextCompat
import java.security.MessageDigest

/**
 * Contact-lock fingerprint collector (3.2.0+).
 *
 * Reads the device's contact list (with explicit READ_CONTACTS permission),
 * normalizes each phone number to a digits-only canonical form, salts each
 * with a per-developer secret, SHA-256-hashes, truncates to 32 hex chars,
 * and returns a stable sorted list.
 *
 * **The SDK never sends raw phone numbers off-device.** Only opaque hashes
 * leave the SDK. The salt is the host app's API key prefix, so the same
 * person on two different developers' apps produces unlinkable contact sets.
 *
 * The host app is responsible for asking the user for the permission via
 * the standard Android runtime-permission flow; this collector simply
 * checks if the permission is currently granted and skips silently if not.
 * That keeps the SDK out of the UI business — developers integrate it the
 * same way they'd integrate any other optional capability.
 */
internal object ContactsCollector {

    /**
     * Returns a sorted list of contact-hash hex strings (32 chars each), or
     * an empty list if the host has no READ_CONTACTS permission, the user
     * has no contacts, or anything throws.
     *
     * Safe to call from any thread but does I/O — call from a background
     * dispatcher.
     *
     * @param apiKey used as the salt source so hashes are scoped per-developer
     */
    fun collect(context: Context, apiKey: String): List<String> {
        if (!hasPermission(context)) return emptyList()
        return try {
            val numbers = readNumbers(context)
            val salt = apiKey.take(16)  // first 16 chars of API key are enough
            val md = MessageDigest.getInstance("SHA-256")
            numbers
                .asSequence()
                .map { normalize(it) }
                .filter { it.length >= 7 }                  // toss garbage entries
                .distinct()
                .map { hashOne(md, salt, it) }
                .toList()
                .sorted()
        } catch (_: Exception) {
            emptyList()
        }
    }

    /** True iff the host process currently holds READ_CONTACTS. */
    fun hasPermission(context: Context): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.READ_CONTACTS) ==
            PackageManager.PERMISSION_GRANTED

    /** Strip everything but digits. Plus signs and country codes still work
     *  because we only care about the numeric tail being stable — same
     *  phone number entered as +972-50-... or 050... produces the same
     *  digits modulo leading-zero / country-prefix swaps, which the user
     *  generally enters the same way per device. */
    private fun normalize(raw: String): String =
        raw.filter { it.isDigit() }

    private fun readNumbers(context: Context): List<String> {
        val out = mutableListOf<String>()
        val uri: Uri = ContactsContract.CommonDataKinds.Phone.CONTENT_URI
        val projection = arrayOf(ContactsContract.CommonDataKinds.Phone.NUMBER)
        // Bounded query — millions of contacts would be pathological; cap
        // at 5000 so a malformed device can't drag startup down. Server
        // also caps the incoming list independently.
        context.contentResolver.query(uri, projection, null, null, null)?.use { c ->
            val col = c.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER)
            if (col < 0) return@use
            var read = 0
            while (c.moveToNext() && read < MAX_RAW_ROWS) {
                val raw = c.getString(col) ?: continue
                if (raw.isNotBlank()) out += raw
                read += 1
            }
        }
        return out
    }

    private fun hashOne(md: MessageDigest, salt: String, normalized: String): String {
        md.reset()
        val digest = md.digest(("$salt:$normalized").toByteArray(Charsets.UTF_8))
        // Truncate to 32 hex chars (16 bytes) — enough to make collisions
        // negligible at < 5000 contacts but small enough that 5000 hashes
        // serialize to ~160 KB JSON.
        return digest.take(16).joinToString("") { "%02x".format(it) }
    }

    private const val MAX_RAW_ROWS = 5000
}
