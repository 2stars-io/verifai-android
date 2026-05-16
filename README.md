# VerifAI Android SDK

Zero-knowledge device trust for Android apps. Verify the **device** holding the password, not just the password itself. Built on the [2Stars VerifAI API](https://api.2stars.io/verifai/v1).

```kotlin
VerifAI.init(applicationContext, "hbs_live_…")
val r = VerifAI.verify(userEmail)
when (r.status) {
    VerifAI.Status.TRUSTED    -> allow()
    VerifAI.Status.NEW_DEVICE -> showApprovalPending(r.sessionId)
    VerifAI.Status.REJECTED   -> blockWith(r.reason)
    else                      -> retry()
}
```

## Install

```gradle
// settings.gradle
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url 'https://jitpack.io' }
    }
}

// app/build.gradle
dependencies {
    implementation 'com.github.2stars-io:verifai-android:3.2.0'
}
```

Min SDK: **24** · Compile SDK: **34** · Kotlin: **1.9+** · Java: **17**.

## What this SDK does

Three independent axes of trust, each opt-in by your API key's feature flags:

| Axis | Catches | Feature flag |
|---|---|---|
| **Device fingerprint** (`signalHashes`) | Cloned device, signal rotation, rooted device | `verifai-patterns` + `verifai-verification` |
| **Behavioral biometrics** (`behavioralHashes`) | Wrong human on right device (touch, motion, keystroke, network class) | `verifai-behavioral` |
| **Server-side patterns** (`patterns`) | Re-registration cadence, multi-user device, long absence, impossible travel | always-on alongside verification |
| **Contact overlap** (`contactHashes`) | Phone swap / restored backup on a different device | `verifai-contact-lock` |
| **Advanced day/hour patterns** | Login outside the user's normal day-of-week + hour bucket | `verifai-advanced-patterns` |

Everything is hashed on-device. The server only ever sees opaque SHA-256 fingerprints — never raw signals or phone numbers.

## Full API surface

| Method | Purpose |
|---|---|
| `init(context, apiKey, options?)` | One-time SDK init in `Application.onCreate` |
| `register(userId)` | First-ever login on this device |
| `verify(userId)` | Every subsequent login |
| `getTrustScore(userId)` | Lookup current trust level + score |
| `listDevices(userId)` | All trusted devices for the user |
| `removeDevice(deviceId, type)` | Forget a device |
| `registerPushToken(userId, fcmToken)` | Wire FCM for cross-device approval |
| `handlePushNotification(data)` | Parse FCM payload → `ApprovalRequest` |
| `approveDevice(sessionId, type)` | Approve another device from this trusted one |
| `rejectDevice(sessionId, type, reason)` | Reject a pending session |
| `isSameNetwork(remoteIP)` | Local IP comparison for proximity gates |
| `attachPasswordField(editText)` | Capture keystroke timing on a password field |
| `startMotionCapture()` / `stopMotionCapture()` | Pair on Activity `onResume`/`onPause` |
| `setContactLockEnabled(enabled)` | Opt in to contact-overlap matching (requires `READ_CONTACTS`) |
| `hasContactsPermission()` / `isContactLockEnabled()` | Status queries for the contact-lock flow |
| `getBehavioralCapture()` | Live counts of captured gestures (debug UI) |

## Response shape (verify)

```kotlin
data class VerificationResult(
    val status: Status,                          // TRUSTED / NEW_DEVICE / PENDING / REJECTED / FEATURE_DISABLED
    val trustScore: Int,                         // 0-100 composite (3.2.0+)
    val trustLevel: TrustLevel,                  // BASELINE / MEDIUM / HIGH / VERY_HIGH
    val deviceId: String?,
    val sessionId: String?,                      // present on NEW_DEVICE
    val scoreBreakdown: Map<String, Int>,        // per-axis 0-100 (3.2.0+)
    val behavioral: BehavioralReport?,
    val patterns: PatternsReport?,
    val strictMode: StrictModeReport?,
    val advanced: AdvancedReport?,               // 3.2.0+
    val contacts: ContactsReport?,               // 3.2.0+
    val error: String?,
)
```

## Versioning

Current: **3.2.0**

- composite trust score + per-axis breakdown
- advanced day/hour patterns
- contact-lock overlap
- 11 behavioral categories (touch / motion / keystroke / network)

## Privacy

- **Raw signals never leave the device.** Every signal is hashed locally with a per-device salt.
- **Contacts** (when contact-lock is on) are SHA-256-hashed with a per-developer salt before upload; the server never sees a phone number.
- **No tracking.** The SDK makes calls only to the API base you configure (default `https://api.2stars.io/verifai/v1`).

## Companion SDKs

- [`@2stars/verifai-web`](https://github.com/2stars-io/verifai-web) — same API surface for browsers
- [`@2stars/video-react`](https://github.com/2stars-io/video-react) — React bindings for the 2Stars video platform
- [OpenAPI spec](https://api.2stars.io/openapi/verifai.json) — generate a client in any language

## License

MIT — see [LICENSE](./LICENSE).
