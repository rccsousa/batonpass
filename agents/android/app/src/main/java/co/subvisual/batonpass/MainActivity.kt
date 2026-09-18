package co.subvisual.batonpass

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.os.PersistableBundle
import android.os.SystemClock
import android.text.InputType
import android.view.View
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

class MainActivity : Activity() {
    private lateinit var store: DeviceStore
    private var enrollment: Enrollment? = null
    private var receiver: Receiver? = null
    private var client: PhoenixClient? = null
    private var resumed = false
    private lateinit var status: TextView
    private lateinit var outcome: TextView
    private lateinit var shared: EditText
    private lateinit var layout: LinearLayout
    private var lastSend = Long.MIN_VALUE

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        store = DeviceStore(this)
        showHome()
        readShare(intent)
    }

    private fun showHome() {
        layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(32), dp(24), dp(24))
            setBackgroundColor(Color.rgb(246, 248, 245))
            fitsSystemWindows = true
            isFocusableInTouchMode = true
        }
        setContentView(ScrollView(this).apply { fitsSystemWindows = true; addView(layout) })
        label("BatonPass", 32f)
        label("Your clipboard, across your devices.", 16f)
        status = label("Not enrolled", 16f)
        outcome = label("", 14f)
        label("Keep this screen open to receive. Offline items are not saved or fetched later.", 14f)
        button("Send clipboard") {
            val manager = getSystemService(ClipboardManager::class.java)
            val clip = manager.primaryClip
            val text = if (clip != null && clip.itemCount > 0) clip.getItemAt(0).text else null
            if (text == null) outcome.text = "Clipboard has no plain text."
            else send(text.toString())
        }
        shared = EditText(this).apply {
            hint = "Text shared to BatonPass"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
            isSaveEnabled = false
            minLines = 2
            maxLines = 5
        }
        layout.addView(shared)
        button("Send this text") { send(shared.text.toString()) }
        button("Enrollment / relay settings") { settings() }
        button("Resume after clock correction") {
            AlertDialog.Builder(this).setTitle("Reset replay protection?")
                .setMessage("First correct the phone's clock. This clears remembered event IDs and can allow a previously received, still-fresh item once more.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Resume") { _, _ ->
                    try {
                        receiver?.resumeAfterClockCorrection() ?: error("Enroll first.")
                        outcome.text = "Receiver resumed."
                    } catch (_: Exception) { outcome.text = "Recovery failed. Check device storage and enrollment." }
                }.show()
        }
        try {
            enrollment = store.enrollment()
            prepareSession()
        } catch (_: Exception) {
            status.text = "Enrollment unavailable. Clear app storage and re-enroll out of band."
        }
    }

    private fun prepareSession() {
        client?.dispose()
        client = null
        val config = enrollment ?: return
        receiver = Receiver(config.key, config.epoch, store, System::currentTimeMillis, SystemClock::elapsedRealtime)
        client = PhoenixClient(config.url, config.topic, { status.text = it }, { frame ->
            if (resumed && hasWindowFocus()) {
                try {
                    val text = receiver!!.accept(frame)
                    val clip = ClipData.newPlainText("BatonPass", text)
                    clip.description.extras = PersistableBundle().apply {
                        putBoolean("android.content.extra.IS_SENSITIVE", true)
                    }
                    getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
                    outcome.text = "Received and copied."
                } catch (_: Exception) {
                    outcome.text = if (receiver?.tripped == true) "Receiver paused. Check clock/storage, then explicitly resume."
                        else "Incoming item rejected."
                }
            }
        }, {
            try { receiver?.checkpoint() } catch (_: Exception) {
                outcome.text = "Receiver paused. Check clock/storage, then explicitly resume."
            }
        })
        outcome.text = if (receiver!!.tripped) "Receiver paused. Check clock/storage, then explicitly resume."
            else "Encryptions this epoch: ${store.sentCount()}"
        if (resumed) client?.start()
    }

    private fun send(text: String) {
        val config = enrollment
        if (config == null || client?.joined != true) { outcome.text = "Connect to the relay first."; return }
        if (!resumed || !hasWindowFocus()) return
        if (text.length > Envelope.MAX_TEXT) { outcome.text = "Text is too large."; return }
        if (receiver?.wasReceived(text) == true) { outcome.text = "This received item will not be forwarded again."; return }
        val now = SystemClock.elapsedRealtime()
        if (lastSend != Long.MIN_VALUE && now - lastSend < 500) return
        try {
            val frame = Envelope.seal(config.key, config.epoch, config.sender, text, System.currentTimeMillis())
            store.recordEncryption()
            lastSend = now
            outcome.text = if (client!!.send(frame)) {
                shared.text.clear()
                "Queued to relay · delivery is best effort, not confirmed."
            } else "Not queued. Wait for connection and try again."
        } catch (_: Exception) { outcome.text = "Could not encrypt. Text must fit within 65,536 UTF-8 bytes." }
    }

    private fun settings() {
        val fields = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(24), 0, dp(24), 0) }
        fun field(label: String, value: String, secret: Boolean = false): EditText {
            fields.addView(TextView(this).apply { text = label })
            return EditText(this).apply {
                setText(value)
                isSingleLine = true
                isSaveEnabled = false
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
                imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
                inputType = InputType.TYPE_CLASS_TEXT or if (secret) InputType.TYPE_TEXT_VARIATION_PASSWORD
                    else InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                fields.addView(this)
            }
        }
        val old = enrollment
        val host = field("Relay Tailscale IPv4:port", old?.host ?: "")
        val group = field("Group", old?.group ?: "home")
        val sender = field("Unique sender ID", old?.sender?.toString() ?: "3")
        val epoch = field("Key epoch", old?.epoch?.toString() ?: "1")
        val key = field(if (old == null) "Group key (64 hex, imported out of band)" else "New key (blank keeps existing)", "", true)
        val error = TextView(this).also(fields::addView)
        val dialog = AlertDialog.Builder(this).setTitle("Enroll this phone")
            .setView(ScrollView(this).apply { addView(fields) })
            .setNegativeButton("Cancel", null).setPositiveButton("Save", null).create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                try {
                    val keyBytes = if (key.text.isEmpty()) old?.key ?: error("Enter the group key.")
                        else key.text.toString().trim().also { require(it.length == 64) }.unhex()
                    val next = Enrollment(host.text.toString().trim(), group.text.toString().trim(),
                        sender.text.toString().toLong(), epoch.text.toString().toLong(), keyBytes)
                    next.validate()
                    // A partially failed rekey must not leave the old in-memory receiver live.
                    client?.dispose()
                    client = null
                    receiver = null
                    store.enroll(next)
                    enrollment = next
                    prepareSession()
                    key.text.clear()
                    dialog.dismiss()
                } catch (_: Exception) {
                    try {
                        enrollment = store.enrollment()
                        prepareSession()
                    } catch (_: Exception) {
                        enrollment = null
                        client?.dispose()
                        client = null
                        receiver = null
                        status.text = "Enrollment unavailable. Clear app storage and re-enroll out of band."
                    }
                    error.text = "Check relay IPv4:port, group, uint32 IDs and 64-hex key. Rekey needs a higher epoch AND new key; keep group/sender unchanged."
                }
            }
        }
        dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        dialog.setOnDismissListener { key.text.clear() }
        dialog.show()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        readShare(intent)
    }

    private fun readShare(intent: Intent) {
        if (intent.action == Intent.ACTION_SEND && intent.type == "text/plain") {
            val text = intent.getCharSequenceExtra(Intent.EXTRA_TEXT)
            if (text != null && text.length <= Envelope.MAX_TEXT) shared.setText(text)
            else outcome.text = "Shared text is missing or too large."
            // Do not retain shared secrets in the activity's launch intent.
            intent.removeExtra(Intent.EXTRA_TEXT)
            intent.clipData = null
        }
    }

    override fun onResume() { super.onResume(); resumed = true; client?.start() }
    override fun onPause() {
        resumed = false
        client?.stop()
        if (receiver?.tripped == false) runCatching { receiver?.checkpoint() }
        super.onPause()
    }
    override fun onDestroy() { client?.dispose(); super.onDestroy() }

    private fun label(value: String, size: Float): TextView = TextView(this).apply {
        text = value; textSize = size; setTextColor(Color.rgb(26, 50, 38))
        setPadding(0, dp(8), 0, dp(12)); this@MainActivity.layout.addView(this)
    }
    private fun button(value: String, action: () -> Unit) {
        layout.addView(Button(this).apply { text = value; isAllCaps = false; setOnClickListener { action() } })
    }
    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
}
