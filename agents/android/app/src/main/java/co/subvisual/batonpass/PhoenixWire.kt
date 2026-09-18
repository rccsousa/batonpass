package co.subvisual.batonpass

object PhoenixWire {
    data class Message(val kind: Int, val join: String?, val ref: String?,
                       val topic: String, val event: String, val payload: ByteArray)

    fun push(join: String, ref: String, topic: String, payload: ByteArray): ByteArray {
        require(payload.size in Envelope.MIN_FRAME..Envelope.MAX_FRAME)
        val fields = listOf(join, ref, topic, "frame").map { it.toByteArray(Charsets.UTF_8) }
        require(fields.all { it.size <= 255 })
        return byteArrayOf(0, *fields.map { it.size.toByte() }.toByteArray()) +
            fields.fold(byteArrayOf()) { acc, bytes -> acc + bytes } + payload
    }

    fun decode(bytes: ByteArray): Message {
        require(bytes.isNotEmpty() && bytes.size <= Envelope.MAX_FRAME + 1025)
        val kind = bytes[0].toInt()
        val count = when (kind) { 0 -> 3; 1 -> 4; 2 -> 2; else -> error("Unknown frame kind") }
        require(bytes.size >= count + 1)
        var offset = count + 1
        val fields = (1..count).map { index ->
            val length = bytes[index].toInt() and 255
            require(offset + length <= bytes.size)
            Envelope.text(bytes.copyOfRange(offset, offset + length)).also { offset += length }
        }
        val payload = bytes.copyOfRange(offset, bytes.size)
        return when (kind) {
            0 -> Message(kind, fields[0], null, fields[1], fields[2], payload)
            1 -> Message(kind, fields[0], fields[1], fields[2], fields[3], payload)
            else -> Message(kind, null, null, fields[0], fields[1], payload)
        }
    }
}
