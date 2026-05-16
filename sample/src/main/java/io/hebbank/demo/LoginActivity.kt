package io.hebbank.demo

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.verifai.sdk.VerifAI
import io.hebbank.demo.databinding.ActivityLoginBinding
import kotlinx.coroutines.launch

/**
 * Bank login → VerifAI verify → dashboard.
 *
 * Two-step flow:
 *   1. Bank password check via /demo-bank/login. On bad creds → show
 *      error, stop here.
 *   2. VerifAI device verify. On TRUSTED → continue to dashboard.
 *      On NEW_DEVICE → register the device (covers first login on
 *      this device) then continue. On REJECTED → block, show the
 *      reason (`different_network` gets a friendlier message).
 */
class LoginActivity : AppCompatActivity() {

    private lateinit var b: ActivityLoginBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityLoginBinding.inflate(layoutInflater)
        setContentView(b.root)

        b.toRegister.setOnClickListener {
            startActivity(Intent(this, RegisterActivity::class.java))
        }
        b.signIn.setOnClickListener { signIn() }

        // Behavioral biometrics — keystroke flight time on password
        // entry. Username is also a meaningful signal but it's typically
        // shorter / autofilled; password gets the full signature value.
        VerifAI.attachPasswordField(b.password)
    }

    override fun onResume() {
        super.onResume()
        // Start IMU motion capture for the duration the user is on the
        // login screen. The freq+amplitude signature contributes the
        // `motionTremor` category to the verify payload.
        VerifAI.startMotionCapture()
    }

    override fun onPause() {
        super.onPause()
        VerifAI.stopMotionCapture()
    }

    private fun signIn() {
        val u = b.username.text.toString().trim()
        val p = b.password.text.toString()
        if (u.isEmpty() || p.isEmpty()) { showError("Fill in both fields"); return }

        b.signIn.isEnabled = false
        b.signIn.text = "Signing in…"
        clearStates()

        lifecycleScope.launch {
            try {
                val r = BankApi.login(this@LoginActivity, u, p)
                BankApi.saveSession(this@LoginActivity, r.token, r.user)
                showVf("Verifying device…", VfTone.PENDING)

                if (BuildConfig.DEMO_API_KEY.isBlank()) {
                    // VerifAI not configured — go straight to dashboard.
                    showVf("Signed in (VerifAI not configured)", VfTone.OK)
                    proceed()
                    return@launch
                }

                val verify = VerifAI.verify(r.user.email)
                when (verify.status) {
                    VerifAI.Status.TRUSTED -> {
                        // Render the behavioral overlay alongside the trust
                        // level when the developer's key has it enabled.
                        // During training the SDK is still accumulating
                        // the baseline; after lock, each login shows MATCH
                        // (or MISMATCH if admin-set to REPORT mode —
                        // block-mode mismatches land in the REJECTED
                        // branch below with reason = behavioral_mismatch).
                        //
                        // The "X/N" denominator is server-driven via
                        // (loginCount + remainingTraining) so the UI
                        // doesn't go stale if the server bumps the
                        // training threshold (5 → 20 → ...).
                        val b9l = verify.behavioral
                        val total = (b9l?.loginCount ?: 0) + (b9l?.remainingTraining ?: 0)

                        // One-shot "baseline locked" announcement —
                        // shown the first time MATCH is observed for
                        // this user. SharedPreferences key is per-email
                        // so two users on the same device each get
                        // their own moment. Persists across reinstalls
                        // ONLY if the prefs file survives backup, which
                        // is fine for the demo.
                        val prefs = getSharedPreferences("vf_behavioral", MODE_PRIVATE)
                        val announcedKey = "baseline_announced_${r.user.email}"
                        val alreadyAnnounced = prefs.getBoolean(announcedKey, false)

                        val isFirstMatch = b9l?.status == VerifAI.BehavioralStatus.MATCH && !alreadyAnnounced

                        val msg = when {
                            b9l?.status == VerifAI.BehavioralStatus.TRAINING ->
                                "✓ Trusted · ${verify.trustLevel} · learning your pattern (${b9l.loginCount}/$total)"
                            isFirstMatch ->
                                "🔒 Baseline locked — your typing rhythm is now your second password ($total logins recorded)"
                            b9l?.status == VerifAI.BehavioralStatus.MATCH ->
                                "✓ Trusted · ${verify.trustLevel} · ✓ pattern match · score ${verify.trustScore}/100"
                            b9l?.status == VerifAI.BehavioralStatus.MISMATCH ->
                                "⚠ Trusted · ${verify.trustLevel} · pattern doesn't match (admin set to report-only)"
                            else ->
                                "✓ Trusted device · ${verify.trustLevel} · score ${verify.trustScore}/100"
                        }
                        if (isFirstMatch) {
                            prefs.edit().putBoolean(announcedKey, true).apply()
                        }
                        showVf(msg, if (b9l?.status == VerifAI.BehavioralStatus.MISMATCH) VfTone.PENDING else VfTone.OK)
                        // Linger ~2.5s on the lock-announce so the user
                        // has time to read it; default 900ms otherwise.
                        proceed(if (isFirstMatch) 2500 else 900)
                    }
                    VerifAI.Status.NEW_DEVICE -> {
                        // First time on this device — auto-register so the
                        // user gets in. Subsequent logins on a brand-new
                        // device that wasn't pre-approved would land here
                        // too; for the demo, register-on-first-attempt is
                        // the simplest UX.
                        VerifAI.register(r.user.email)
                        showVf("✓ First time on this device — registered with the bank", VfTone.OK)
                        proceed(1200)
                    }
                    VerifAI.Status.REJECTED -> {
                        BankApi.clearSession(this@LoginActivity)
                        // Distinguish the rejection reason — the demo's three
                        // possible REJECTED paths are:
                        //   - 'behavioral_mismatch' (verifai-behavioral-block ON
                        //     and the swipe/tap pattern didn't match the
                        //     locked baseline) — the wife test outcome
                        //   - 'different_network' (verifai-same-network-only
                        //     ON and the IP didn't match a trusted IP)
                        //   - any other server-side rejection
                        val behavioralMismatch = verify.behavioral?.status == VerifAI.BehavioralStatus.MISMATCH
                        val msg = when {
                            behavioralMismatch -> {
                                val cats = verify.behavioral?.mismatches.orEmpty()
                                val detail = if (cats.isEmpty()) "" else " (${cats.joinToString(" + ")})"
                                "✗ Login blocked — this doesn't look like the usual user.$detail"
                            }
                            verify.error?.contains("different_network") == true ||
                            verify.deviceId.orEmpty().contains("different_network") ->
                                "✗ Login blocked — this device is on a different network from your trusted device. Try again from the trusted WiFi."
                            else ->
                                "✗ Login blocked: ${verify.error ?: "rejected"}"
                        }
                        showVf(msg, VfTone.BAD)
                        b.signIn.isEnabled = true
                        b.signIn.text = "Sign in"
                    }
                    VerifAI.Status.FEATURE_DISABLED -> {
                        showVf("⚠ VerifAI disabled by admin — proceeding anyway for demo", VfTone.OK)
                        proceed(1200)
                    }
                    else -> {
                        showVf("⚠ ${verify.status}: ${verify.error ?: ""} — proceeding for demo", VfTone.OK)
                        proceed(1200)
                    }
                }
            } catch (e: Exception) {
                showError(e.message ?: "Login failed")
                b.signIn.isEnabled = true
                b.signIn.text = "Sign in"
            }
        }
    }

    private fun proceed(delayMs: Long = 0L) {
        b.root.postDelayed({
            startActivity(Intent(this, DashboardActivity::class.java))
            finish()
        }, delayMs)
    }

    private fun clearStates() { b.errorBox.visibility = View.GONE; b.vfStatus.visibility = View.GONE }
    private fun showError(m: String) { b.errorBox.text = m; b.errorBox.visibility = View.VISIBLE; b.vfStatus.visibility = View.GONE }

    private enum class VfTone { OK, PENDING, BAD }
    private fun showVf(m: String, tone: VfTone) {
        b.errorBox.visibility = View.GONE
        b.vfStatus.text = m
        b.vfStatus.visibility = View.VISIBLE
        b.vfStatus.setBackgroundResource(when (tone) {
            VfTone.OK      -> R.drawable.bg_alert_ok
            VfTone.PENDING -> R.drawable.bg_alert_pending
            VfTone.BAD     -> R.drawable.bg_alert_bad
        })
    }
}
