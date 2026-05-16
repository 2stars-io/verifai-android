package io.hebbank.demo

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Tiny REST client for the demo bank backend (the `/api/v1/demo-bank/...`
 * routes — written without the slash-star wildcard because Kotlin's block
 * comments nest, and a literal `/` followed by `*` inside this KDoc would
 * open an inner block comment that never closes and silently swallow the
 * entire BankApi class).
 *
 * Stays purposely small — no Retrofit, no OkHttp, just HttpURLConnection
 * + JSONObject. The real selling point of this sample is the VerifAI
 * integration; the bank API is just plumbing to make the flow visible.
 */
object BankApi {

    private const val PREFS = "hebbank_session"
    private const val PREF_TOKEN = "token"
    private const val PREF_USER  = "user_json"

    data class User(
        val id: String,
        val email: String,
        val username: String,
        val name: String,
        val balance: String,
        val balanceCents: Long,
    )

    data class LoginResult(val token: String, val user: User)
    data class BankConfig(val apiKey: String?, val verifaiBase: String, val sameNetwork: Boolean, val configured: Boolean)

    private fun base(context: Context): String = BuildConfig.BANK_BASE_URL.trimEnd('/') + "/api/v1/demo-bank"

    // ── Session storage ─────────────────────────────────────────────

    fun saveSession(context: Context, token: String, user: User) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(PREF_TOKEN, token)
            .putString(PREF_USER, JSONObject().apply {
                put("id", user.id)
                put("email", user.email)
                put("username", user.username)
                put("name", user.name)
                put("balance", user.balance)
                put("balanceCents", user.balanceCents)
            }.toString())
            .apply()
    }

    fun loadSession(context: Context): Pair<String, User>? {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val token = prefs.getString(PREF_TOKEN, null) ?: return null
        val userJson = prefs.getString(PREF_USER, null) ?: return null
        return try {
            val o = JSONObject(userJson)
            token to User(
                id = o.optString("id"),
                email = o.optString("email"),
                username = o.optString("username"),
                name = o.optString("name"),
                balance = o.optString("balance", "0.00"),
                balanceCents = o.optLong("balanceCents", 0L),
            )
        } catch (e: Exception) { null }
    }

    fun clearSession(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()
    }

    // ── Endpoints ──────────────────────────────────────────────────

    suspend fun register(context: Context, email: String, username: String, name: String, password: String): LoginResult = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("email", email); put("username", username); put("name", name); put("password", password)
        }
        val resp = post("${base(context)}/register", null, body)
        LoginResult(resp.getString("token"), userFromJson(resp.getJSONObject("user")))
    }

    suspend fun login(context: Context, usernameOrEmail: String, password: String): LoginResult = withContext(Dispatchers.IO) {
        val body = JSONObject().apply { put("username", usernameOrEmail); put("password", password) }
        val resp = post("${base(context)}/login", null, body)
        LoginResult(resp.getString("token"), userFromJson(resp.getJSONObject("user")))
    }

    suspend fun me(context: Context, token: String): User = withContext(Dispatchers.IO) {
        val resp = get("${base(context)}/me", token)
        userFromJson(resp.getJSONObject("user"))
    }

    suspend fun transfer(context: Context, token: String, toUsername: String, amountCents: Long): User = withContext(Dispatchers.IO) {
        val body = JSONObject().apply { put("toUsername", toUsername); put("amountCents", amountCents) }
        val resp = post("${base(context)}/transfer", token, body)
        userFromJson(resp.getJSONObject("user"))
    }

    suspend fun config(context: Context): BankConfig = withContext(Dispatchers.IO) {
        val resp = get("${base(context)}/config", null)
        BankConfig(
            apiKey      = resp.optString("apiKey").takeIf { it.isNotBlank() },
            verifaiBase = resp.optString("verifaiBase", "/api/v1/verifai"),
            sameNetwork = resp.optBoolean("sameNetwork", false),
            configured  = resp.optBoolean("configured", false),
        )
    }

    // ── HTTP helpers ───────────────────────────────────────────────

    private fun userFromJson(o: JSONObject) = User(
        id = o.optString("id"),
        email = o.optString("email"),
        username = o.optString("username"),
        name = o.optString("name"),
        balance = o.optString("balance", "0.00"),
        balanceCents = o.optLong("balanceCents", 0L),
    )

    private fun get(url: String, token: String?): JSONObject = exec(url, "GET", token, null)
    private fun post(url: String, token: String?, body: JSONObject): JSONObject = exec(url, "POST", token, body)

    private fun exec(url: String, method: String, token: String?, body: JSONObject?): JSONObject {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept", "application/json")
            if (token != null) setRequestProperty("Authorization", "Bearer $token")
            connectTimeout = 15_000
            readTimeout = 15_000
        }
        if (body != null) {
            conn.doOutput = true
            conn.outputStream.bufferedWriter().use { it.write(body.toString()) }
        }
        val code = conn.responseCode
        val text = (if (code in 200..299) conn.inputStream else conn.errorStream)
            ?.bufferedReader()?.readText() ?: ""
        if (code in 200..299) return JSONObject(text.ifBlank { "{}" })
        val msg = try {
            JSONObject(text).optJSONObject("error")?.optString("message")
        } catch (_: Exception) { null }
        throw RuntimeException(msg ?: "Bank HTTP $code")
    }
}
