package co.subvisual.batonpass

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

@RunWith(Parameterized::class)
class VectorTest(private val name: String, private val vector: JSONObject) {
    companion object {
        private val root = JSONObject(VectorTest::class.java.getResource("/vectors.json")!!.readText())
        @JvmStatic @Parameterized.Parameters(name = "{0}")
        fun vectors(): List<Array<Any>> = root.getJSONArray("vectors").let { vectors ->
            (0 until vectors.length()).map { i -> vectors.getJSONObject(i).let { arrayOf(it.getString("name"), it) } }
        }
    }

    @Test fun matchesSharedContract() {
        val frame = vector.getString("frameHex").unhex()
        val key = root.getString("keyHex").unhex()
        if (vector.getBoolean("mustReject")) {
            assertThrows(Exception::class.java) { Envelope.open(key, frame) }
        } else {
            val expected = vector.getString("plaintextHex").unhex()
            assertArrayEquals(expected, Envelope.open(key, frame))
            val h = Envelope.header(frame)
            assertArrayEquals(frame, Envelope.sealBytes(key, h.epoch, h.sender, expected, h.timestamp,
                h.eventId.unhex(), frame.copyOfRange(33, 45)))
        }
    }
}

class ProtocolTest {
    @Test fun malformedWireRejectedAndServerShapesAreDistinct() {
        for (frame in listOf(byteArrayOf(), byteArrayOf(2), byteArrayOf(0, 1, 2),
            byteArrayOf(2, 127, 127), byteArrayOf(3, 0, 0))) {
            assertThrows(Exception::class.java) { PhoenixWire.decode(frame) }
        }
        val payload = ByteArray(61) { 42 }
        val topic = "clipboard:home".toByteArray()
        val event = "frame".toByteArray()
        val broadcast = byteArrayOf(2, topic.size.toByte(), 5) + topic + event + payload
        val push = byteArrayOf(0, 1, topic.size.toByte(), 5) + "1".toByteArray() + topic + event + payload
        for (bytes in listOf(broadcast, push)) {
            val decoded = PhoenixWire.decode(bytes)
            assertEquals("clipboard:home", decoded.topic)
            assertEquals("frame", decoded.event)
            assertArrayEquals(payload, decoded.payload)
        }
        val outgoing = PhoenixWire.push("1", "2", "clipboard:home", payload)
        assertArrayEquals(byteArrayOf(0, 1, 1, 14, 5), outgoing.copyOfRange(0, 5))
        assertEquals("12clipboard:homeframe", String(outgoing.copyOfRange(5, 26)))
    }

    @Test fun enrollmentConfinesCleartextTransportToTailnet() {
        fun config(host: String) = Enrollment(host, "home", 3, 1, ByteArray(32))
        config("100.64.0.10:4000").validate()
        config("100.127.255.254:4000").validate()
        for (host in listOf("example.com:4000", "127.0.0.1:4000", "100.63.0.1:4000",
            "100.128.0.1:4000", "100.64.0.10", "user@100.64.0.10:4000",
            "100.64.0.10:4000/evil", "100.64.0.10:0", "100.064.0.10:4000")) {
            assertThrows(host, Exception::class.java) { config(host).validate() }
        }
    }

    @Test fun sendBoundsUtf8BytesAndPreservesWhitespace() {
        val key = ByteArray(32)
        val text = " 012345\r\n😊 "
        assertEquals(text, Envelope.text(Envelope.open(key, Envelope.seal(key, 1, 3, text, 100))))
        assertThrows(Exception::class.java) { Envelope.seal(key, 1, 3, "😊".repeat(20_000), 100) }
        assertThrows(Exception::class.java) { Envelope.text(byteArrayOf(0xff.toByte())) }
        assertFalse(Envelope.seal(key, 1, 3, text, 100).contentEquals(Envelope.seal(key, 1, 3, text, 100)))
    }
}
