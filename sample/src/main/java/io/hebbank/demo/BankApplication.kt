package io.hebbank.demo

import android.app.Application
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.verifai.sdk.VerifAI

/**
 * App-level singleton — the canonical place for one-time SDK init.
 *
 * Why this exists (vs. initializing in MainActivity.onCreate as we did
 * before): Android can warm-start the app straight into a non-launcher
 * Activity (LoginActivity, DashboardActivity) hours after the user
 * last touched it, without ever re-running MainActivity. That happens
 * any time the OS reaps a cached process under memory pressure but
 * keeps the activity stack metadata around. When the user comes back,
 * Android restores the top Activity directly. MainActivity is skipped,
 * VerifAI.init() never runs, and the static `isInitialized = false`
 * trips the next SDK call with "VerifAI SDK not initialized."
 *
 * Application.onCreate() is GUARANTEED to run once per process before
 * any Activity, regardless of how the OS launches the app — cold
 * launch, warm launch, restored from process death, deep link,
 * notification tap, etc. That's why every Android-SDK init guide
 * recommends doing it here.
 *
 * Wired in AndroidManifest.xml via android:name on <application>.
 */
class BankApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        val key = BuildConfig.DEMO_API_KEY
        if (key.isNotBlank()) {
            VerifAI.init(
                applicationContext, key,
                // Public path is /verifai/v1 on api.2stars.io; the
                // edge rewrites it to internal /api/v1/verifai. For
                // the demo, BANK_BASE_URL points at the same host
                // serving both products, so just append the public
                // VerifAI prefix.
                VerifAI.Options(
                    baseUrl = BuildConfig.BANK_BASE_URL.trimEnd('/') + "/verifai/v1",
                ),
            )
            android.util.Log.i("BankApp", "VerifAI.init() called from Application.onCreate (this should fire on every process start)")
        } else {
            android.util.Log.w("BankApp", "DEMO_API_KEY blank — VerifAI not initialized")
        }

        // Auto-logout: when the whole app process goes to background
        // (last activity stopped — home button, recents swipe, switch
        // to another app), wipe the bank session token. Next launch
        // forces a fresh login. Matches the bank-grade behaviour the
        // demo is supposed to model: no "still logged in" surprise
        // after handing the phone to someone else.
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStop(owner: LifecycleOwner) {
                BankApi.clearSession(applicationContext)
                android.util.Log.i("BankApp", "auto-logout: bank session cleared on ON_STOP")
            }
        })
    }
}
