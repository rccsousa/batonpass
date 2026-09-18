package co.subvisual.batonpass

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import org.json.JSONObject
import java.io.File
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Keystore wrapping key never leaves Android. All files are excluded from backup. */
class DeviceStore(context: Context, namespace: String = "batonpass") : ReplayStore {
    private val directory = File(context.noBackupFilesDir, namespace).apply { mkdirs() }
    private val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val alias = "$namespace.storage.v1"

    private fun storageKey(): SecretKey = keystore.getKey(alias, null) as? SecretKey
        ?: error("Device key unavailable. Re-enrollment is required.")

    private fun createKey() {
        check(!keystore.containsAlias(alias))
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).build())
        }.generateKey()
    }

    private fun read(name: String): JSONObject {
        val file = AtomicFile(File(directory, name))
        val bytes = file.openRead().use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                require(output.size() + count <= 1_048_576)
                output.write(buffer, 0, count)
            }
            val result = output.toByteArray()
            require(result.size in 29..1_048_576)
            result
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, storageKey(), GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
        cipher.updateAAD(name.toByteArray(Charsets.UTF_8))
        return JSONObject(Envelope.text(cipher.doFinal(bytes, 12, bytes.size - 12)))
    }

    private fun write(name: String, value: JSONObject) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, storageKey())
        cipher.updateAAD(name.toByteArray(Charsets.UTF_8))
        val bytes = cipher.iv + cipher.doFinal(value.toString().toByteArray(Charsets.UTF_8))
        val file = AtomicFile(File(directory, name))
        val stream = file.startWrite()
        try {
            stream.write(bytes)
            // Throw on fsync failure; AtomicFile.finishWrite itself only logs it.
            stream.fd.sync()
            file.finishWrite(stream)
        } catch (e: Exception) { file.failWrite(stream); throw e }
    }

    fun enrollment(): Enrollment? {
        val config = File(directory, "enrollment")
        if (!config.exists() && !File(directory, "enrollment.bak").exists()) {
            check(!keystore.containsAlias(alias) && directory.listFiles().orEmpty().isEmpty()) {
                "Enrollment state missing. Clear app storage and re-enroll out of band."
            }
            return null
        }
        val json = read("enrollment")
        return Enrollment(json.getString("host"), json.getString("group"), json.getLong("sender"),
            json.getLong("epoch"), json.getString("key").unhex()).also { it.validate() }
    }

    fun enroll(next: Enrollment) {
        next.validate()
        val old = enrollment()
        if (old != null && !next.sameIdentity(old)) {
            require(next.group == old.group && next.sender == old.sender && next.epoch > old.epoch &&
                !next.key.contentEquals(old.key)) {
                "Rekey requires a higher epoch and a new key; group and sender must stay unchanged."
            }
        }
        if (old == null) createKey()
        if (old == null || !next.sameIdentity(old)) {
            // Trip first so an interrupted enrollment cannot quietly reset replay protection.
            writeAnchor(ReplayAnchor(0, true))
            writeState(ReplayState(0, System.currentTimeMillis(), emptyMap()))
            write("enrollment", JSONObject().put("host", next.host).put("group", next.group)
                .put("sender", next.sender).put("epoch", next.epoch).put("key", next.key.hex()))
            writeAnchor(ReplayAnchor(0, false))
            write("sent", JSONObject().put("count", 0))
        } else {
            // Endpoint edits and repeated Save must never clear dedup state.
            write("enrollment", JSONObject().put("host", next.host).put("group", next.group)
                .put("sender", next.sender).put("epoch", next.epoch).put("key", next.key.hex()))
        }
    }

    override fun state(): ReplayState {
        val json = read("replay")
        val entries = json.getJSONObject("entries")
        require(entries.length() <= 4096)
        return ReplayState(json.getLong("counter"), json.getLong("wall"),
            entries.keys().asSequence().associateWith { entries.getLong(it) },
            if (json.isNull("lastReceivedHash")) null else json.getString("lastReceivedHash"))
    }

    override fun anchor(): ReplayAnchor = read("anchor").let {
        ReplayAnchor(it.getLong("counter"), it.getBoolean("tripped"))
    }

    override fun writeState(state: ReplayState) = write("replay", JSONObject()
        .put("counter", state.counter).put("wall", state.wall).put("entries", JSONObject(state.entries))
        .put("lastReceivedHash", state.lastReceivedHash ?: JSONObject.NULL))

    override fun writeAnchor(anchor: ReplayAnchor) = write("anchor", JSONObject()
        .put("counter", anchor.counter).put("tripped", anchor.tripped))

    fun sentCount() = runCatching { read("sent").getLong("count") }.getOrDefault(0)
    fun recordEncryption() {
        // Observability only, not a nonce source or a gate (SPEC §6).
        runCatching { write("sent", JSONObject().put("count", sentCount() + 1)) }
    }
}
