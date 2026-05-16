package io.hebbank.demo

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity

/**
 * Splash + router. Routes to LoginActivity / DashboardActivity based on
 * whether a bank session is already stored locally.
 *
 * VerifAI SDK init lives in [BankApplication.onCreate] — Android can
 * warm-start the app straight into LoginActivity / DashboardActivity
 * without running MainActivity, so init MUST be in the Application
 * class to be present on every entry path.
 */
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val session = BankApi.loadSession(this)
        val next = if (session != null) DashboardActivity::class.java else LoginActivity::class.java
        startActivity(Intent(this, next))
        finish()
    }
}
