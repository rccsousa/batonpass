package co.subvisual.batonpass

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Byte-exact crypto/SPEC.md v1.1. No platform clipboard or persistence code. */
object Envelope {
    const val MAX_TEXT = 65_536
    const val MIN_FRAME = 61
    const val MAX_FRAME = 65_597
    private val random = SecureRandom()

    data class Header(val epoch: Long, val eventId: String, val sender: Long, val timestamp: Long)

    fun header(frame: ByteArray): Header {
        require(frame.size in MIN_FRAME..MAX_FRAME && frame[0] == 1.toByte())
        val b = ByteBuffer.wrap(frame)
        b.get()
        val epoch = b.int.toLong() and 0xffffffffL
        val event = ByteArray(16).also { b.get(it) }
        return Header(epoch, event.hex(), b.int.toLong() and 0xffffffffL, b.long)
    }

    fun seal(key: ByteArray, epoch: Long, sender: Long, text: String, now: Long): ByteArray {
        // Bound UTF-16 input before the UTF-8 allocation as well.
        require(text.length <= MAX_TEXT)
        val plaintext = text.toByteArray(Charsets.UTF_8)
        require(plaintext.size <= MAX_TEXT)
        return sealBytes(key, epoch, sender, plaintext, now,
            ByteArray(16).also(random::nextBytes), ByteArray(12).also(random::nextBytes))
    }

    internal fun sealBytes(key: ByteArray, epoch: Long, sender: Long, plaintext: ByteArray,
                          timestamp: Long, event: ByteArray, nonce: ByteArray): ByteArray {
        require(key.size == 32 && epoch in 0..0xffffffffL && sender in 0..0xffffffffL)
        require(plaintext.size <= MAX_TEXT && event.size == 16 && nonce.size == 12)
        val header = ByteBuffer.allocate(33).put(1).putInt(epoch.toInt()).put(event)
            .putInt(sender.toInt()).putLong(timestamp).array()
        val cipher = cipher()
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        cipher.updateAAD(header)
        return header + nonce + cipher.doFinal(plaintext)
    }

    fun open(key: ByteArray, frame: ByteArray): ByteArray {
        header(frame)
        require(key.size == 32)
        val cipher = cipher()
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"),
            IvParameterSpec(frame.copyOfRange(33, 45)))
        cipher.updateAAD(frame, 0, 33)
        return cipher.doFinal(frame, 45, frame.size - 45)
    }

    // Android Conscrypt and desktop SunJCE use different transformation names.
    private fun cipher(): Cipher = try {
        Cipher.getInstance("ChaCha20/Poly1305/NoPadding")
    } catch (_: java.security.NoSuchAlgorithmException) {
        Cipher.getInstance("ChaCha20-Poly1305")
    }

    fun text(bytes: ByteArray): String = Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes)).toString()
}

internal fun ByteArray.hex() = joinToString("") { "%02x".format(it.toInt() and 255) }
internal fun String.unhex(): ByteArray {
    require(length % 2 == 0 && all { it in "0123456789abcdefABCDEF" })
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
