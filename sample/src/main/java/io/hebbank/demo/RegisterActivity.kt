package io.hebbank.demo

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.verifai.sdk.VerifAI
import io.hebbank.demo.databinding.ActivityRegisterBinding
import kotlinx.coroutines.launch

class RegisterActivity : AppCompatActivity() {
    private lateinit var b: ActivityRegisterBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityRegisterBinding.inflate(layoutInflater)
        setContentView(b.root)
        b.toLogin.setOnClickListener {
            startActivity(Intent(this, LoginActivity::class.java)); finish()
        }
        b.openAccount.setOnClickListener { register() }
    }

    private fun register() {
        val firstName = b.firstName.text.toString().trim()
        val lastName  = b.lastName.text.toString().trim()
        val username  = b.username.text.toString().trim().lowercase()
        val password  = b.password.text.toString()
        if (firstName.isEmpty() || lastName.isEmpty() || username.isEmpty() || password.isEmpty()) {
            showError("Fill in every field"); return
        }
        // Combine first + last for the backend's `name` column.
        val name  = "$firstName $lastName"
        // Backend requires email; we auto-generate from username so the
        // user only sees the 4 fields they asked for. The synthetic
        // address never receives mail — it's just an identifier.
        val email = "$username@verifai-test.local"

        b.openAccount.isEnabled = false
        b.openAccount.text = "Opening account…"
        b.errorBox.visibility = View.GONE

        lifecycleScope.launch {
            try {
                val r = BankApi.register(this@RegisterActivity, email, username, name, password)
                BankApi.saveSession(this@RegisterActivity, r.token, r.user)

                // Register the device with VerifAI on first-ever signup —
                // builds the trust profile from this device's signal hashes.
                if (BuildConfig.DEMO_API_KEY.isNotBlank()) {
                    try { VerifAI.register(r.user.email) } catch (_: Exception) { /* not fatal */ }
                }
                startActivity(Intent(this@RegisterActivity, DashboardActivity::class.java))
                finish()
            } catch (e: Exception) {
                showError(e.message ?: "Registration failed")
                b.openAccount.isEnabled = true
                b.openAccount.text = "Open my account"
            }
        }
    }

    private fun showError(m: String) { b.errorBox.text = m; b.errorBox.visibility = View.VISIBLE }
}
