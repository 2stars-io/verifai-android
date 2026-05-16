package io.hebbank.demo

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.verifai.sdk.VerifAI
import io.hebbank.demo.databinding.ActivityDashboardBinding
import kotlinx.coroutines.launch

class DashboardActivity : AppCompatActivity() {

    private lateinit var b: ActivityDashboardBinding
    private var token: String = ""
    private var user: BankApi.User? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityDashboardBinding.inflate(layoutInflater)
        setContentView(b.root)

        val session = BankApi.loadSession(this)
        if (session == null) { backToLogin(); return }
        token = session.first
        user = session.second
        renderUser()
        loadVerifaiPanel()

        b.signOut.setOnClickListener {
            BankApi.clearSession(this); backToLogin()
        }
        b.send.setOnClickListener { transfer() }
    }

    private fun renderUser() {
        val u = user ?: return
        b.greeting.text = "Hi, ${u.name.split(" ").firstOrNull() ?: u.username} 👋"
        b.who.text = "@${u.username}"
        b.balance.text = "$${"%,.2f".format(u.balanceCents / 100.0)}"
        b.acct.text = "···· ···· ···· " + u.id.takeLast(4).uppercase()
    }

    private fun transfer() {
        val to = b.transferTo.text.toString().trim().removePrefix("@").lowercase()
        val amt = b.transferAmount.text.toString().toDoubleOrNull() ?: 0.0
        if (to.isEmpty() || amt <= 0) {
            b.transferStatus.text = "Enter a username and a positive amount"
            b.transferStatus.visibility = View.VISIBLE; return
        }
        b.send.isEnabled = false; b.send.text = "Sending…"
        b.transferStatus.visibility = View.GONE

        lifecycleScope.launch {
            try {
                val u = BankApi.transfer(this@DashboardActivity, token, to, (amt * 100).toLong())
                user = u
                BankApi.saveSession(this@DashboardActivity, token, u)
                renderUser()
                b.transferStatus.text = "Sent $${"%.2f".format(amt)} to @$to"
                b.transferStatus.visibility = View.VISIBLE
                b.transferTo.text?.clear(); b.transferAmount.text?.clear()
            } catch (e: Exception) {
                b.transferStatus.text = e.message ?: "Transfer failed"
                b.transferStatus.visibility = View.VISIBLE
            } finally {
                b.send.isEnabled = true; b.send.text = "Send"
            }
        }
    }

    private fun loadVerifaiPanel() {
        val u = user ?: return
        if (BuildConfig.DEMO_API_KEY.isBlank()) {
            b.vfTitle.text = "VerifAI not configured"
            b.vfMeta.text  = "Set demoApiKey in build.gradle props to enable device trust"
            return
        }
        lifecycleScope.launch {
            try {
                val cfg = BankApi.config(this@DashboardActivity)
                val ts = VerifAI.getTrustScore(u.email)
                b.vfTitle.text = if (ts.level == VerifAI.TrustLevel.BASELINE)
                    "Newly registered device · score ${ts.score}/100"
                else
                    "Trusted device · ${ts.level} · score ${ts.score}/100"
                b.vfMeta.text = "${ts.loginCount} logins · ${ts.ageInDays} days · same-network gate ${if (cfg.sameNetwork) "ON" else "OFF"}"

                val devices = VerifAI.listDevices(u.email)
                b.devicesList.removeAllViews()
                if (devices.isEmpty()) {
                    val tv = android.widget.TextView(this@DashboardActivity).apply { text = "No devices yet."; setTextColor(0xFF64748B.toInt()); textSize = 13f }
                    b.devicesList.addView(tv)
                } else {
                    for (d in devices) {
                        val row = layoutInflater.inflate(R.layout.row_device, b.devicesList, false)
                        row.findViewById<android.widget.TextView>(R.id.deviceName).text = d.name
                        val tier = when {
                            d.lastUsed != null && (System.currentTimeMillis() - d.createdAt) > 0 -> "trusted"
                            else -> "new"
                        }
                        row.findViewById<android.widget.TextView>(R.id.deviceMeta).text =
                            "${d.id.take(16)}… · last seen ${java.text.SimpleDateFormat("MMM d", java.util.Locale.US).format(java.util.Date(d.lastUsed ?: d.createdAt))}"
                        b.devicesList.addView(row)
                    }
                }
            } catch (e: Exception) {
                b.vfTitle.text = "VerifAI status unavailable"
                b.vfMeta.text  = e.message ?: ""
            }
        }
    }

    private fun backToLogin() {
        startActivity(Intent(this, LoginActivity::class.java))
        finish()
    }
}
