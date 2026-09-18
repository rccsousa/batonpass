package co.subvisual.batonpass

import android.content.Intent
import android.os.SystemClock
import android.test.InstrumentationTestCase
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.atomic.AtomicInteger

@Suppress("DEPRECATION")
class AndroidIntegrationTest : InstrumentationTestCase() {
    fun testAllSharedVectorsOnAndroidCryptoProvider() {
        val root = JSONObject(instrumentation.context.assets.open("vectors.json").bufferedReader().use { it.readText() })
        val vectors = root.getJSONArray("vectors")
        val key = root.getString("keyHex").unhex()
        for (i in 0 until vectors.length()) {
            val vector = vectors.getJSONObject(i)
            val frame = vector.getString("frameHex").unhex()
            val result = runCatching { Envelope.open(key, frame) }
            if (vector.getBoolean("mustReject")) assertTrue(vector.getString("name"), result.isFailure)
            else {
                assertEquals(vector.getString("name"), vector.getString("plaintextHex"), result.getOrThrow().hex())
                val h = Envelope.header(frame)
                assertEquals(frame.hex(), Envelope.sealBytes(key, h.epoch, h.sender, result.getOrThrow(),
                    h.timestamp, h.eventId.unhex(), frame.copyOfRange(33, 45)).hex())
            }
        }
    }

    fun testEncryptedEnrollmentReplayRestartAndRekey() {
        val context = instrumentation.targetContext
        val namespace = "test-${UUID.randomUUID()}"
        val dir = File(context.noBackupFilesDir, namespace)
        try {
            val store = DeviceStore(context, namespace)
            assertNull(store.enrollment())
            val config = Enrollment("100.64.0.10:4000", "home", 3, 1, ByteArray(32) { it.toByte() })
            store.enroll(config)
            val reloaded = DeviceStore(context, namespace)
            assertTrue(config.sameIdentity(reloaded.enrollment()!!))
            val now = System.currentTimeMillis()
            val frame = Envelope.seal(config.key, 1, 4, "012345", now)
            fun receiver() = Receiver(config.key, 1, reloaded, System::currentTimeMillis, SystemClock::elapsedRealtime)
            assertEquals("012345", receiver().accept(frame))
            assertTrue(receiver().wasReceived("012345"))
            assertTrue(runCatching { receiver().accept(frame) }.isFailure)
            store.enroll(config.copy(host = "100.64.0.20:4000"))
            assertEquals(1L, store.state().counter)
            assertTrue(runCatching { store.enroll(config.copy(epoch = 2)) }.isFailure)
            assertTrue(runCatching { store.enroll(config.copy(key = ByteArray(32) { 42 })) }.isFailure)
            for (file in dir.listFiles()!!) {
                val bytes = file.readBytes()
                assertFalse(String(bytes).contains(config.key.hex()))
                assertFalse(String(bytes).contains("012345"))
            }
            // A missing cache is not treated as a fresh installation.
            assertTrue(File(dir, "replay").delete())
            assertTrue(receiver().tripped)
            receiver().also { it.resumeAfterClockCorrection(); assertFalse(it.tripped) }
            store.enroll(config.copy(epoch = 2, key = ByteArray(32) { 42 }))
            assertEquals(2L, store.enrollment()!!.epoch)
            assertEquals(0L, store.state().counter)
        } finally {
            dir.deleteRecursively()
            KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry("$namespace.storage.v1") }
        }
    }

    fun testJoinGateBinaryRoundTripAndForegroundStop() {
        val server = MockWebServer()
        val joined = CountDownLatch(1)
        val rejoined = CountDownLatch(1)
        val joins = AtomicInteger()
        val received = CountDownLatch(1)
        val pushed = CountDownLatch(1)
        val joinRequested = CountDownLatch(1)
        val peer = AtomicReference<WebSocket>()
        val payload = Envelope.seal(ByteArray(32), 1, 4, "test", System.currentTimeMillis())
        server.enqueue(MockResponse().withWebSocketUpgrade(object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) { peer.set(webSocket) }
            override fun onMessage(webSocket: WebSocket, text: String) {
                val message = JSONArray(text)
                if (message.getString(3) == "phx_join") joinRequested.countDown()
            }
            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                val sent = bytes.toByteArray()
                // Verify outgoing client-to-server header, not the asymmetric server decoder.
                val offset = 5 + (1..4).sumOf { sent[it].toInt() and 255 }
                if (sent.copyOfRange(offset, sent.size).contentEquals(payload)) pushed.countDown()
            }
        }))
        server.start()
        val url = server.url("/socket/websocket?vsn=2.0.0").toString()
        lateinit var client: PhoenixClient
        try {
            instrumentation.runOnMainSync {
                client = PhoenixClient(url, "clipboard:home",
                    { if (it.startsWith("Connected")) {
                        if (joins.incrementAndGet() == 1) joined.countDown() else rejoined.countDown()
                    } },
                    { if (it.contentEquals(payload)) received.countDown() }, {})
                client.start()
                assertFalse(client.send(payload))
            }
            assertTrue(joinRequested.await(5, TimeUnit.SECONDS))
            instrumentation.runOnMainSync { assertFalse(client.joined); assertFalse(client.send(payload)) }
            peer.get().send("[\"1\",\"1\",\"clipboard:home\",\"phx_reply\",{\"status\":\"ok\",\"response\":{}}]")
            assertTrue(joined.await(5, TimeUnit.SECONDS))
            instrumentation.runOnMainSync { assertTrue(client.send(payload)) }
            assertTrue(pushed.await(5, TimeUnit.SECONDS))
            peer.get().send((byteArrayOf(2, 14, 5) + "clipboard:homeframe".toByteArray() + payload).toByteString())
            assertTrue(received.await(5, TimeUnit.SECONDS))
            instrumentation.runOnMainSync { client.stop(); assertFalse(client.joined); assertFalse(client.send(payload)) }
            server.enqueue(MockResponse().withWebSocketUpgrade(object : WebSocketListener() {
                override fun onMessage(webSocket: WebSocket, text: String) {
                    if (JSONArray(text).getString(3) == "phx_join") {
                        webSocket.send("[\"1\",\"1\",\"clipboard:home\",\"phx_reply\",{\"status\":\"ok\",\"response\":{}}]")
                    }
                }
            }))
            instrumentation.runOnMainSync { client.start() }
            assertTrue(rejoined.await(5, TimeUnit.SECONDS))
            instrumentation.runOnMainSync { assertTrue(client.joined) }
        } finally {
            instrumentation.runOnMainSync { client.dispose() }
            server.close()
        }
    }

    fun testRelayRedirectCannotEscapeConfiguredEndpoint() {
        val source = MockWebServer()
        val destination = MockWebServer()
        destination.start()
        source.enqueue(MockResponse().setResponseCode(302).setHeader("Location", destination.url("/escape")))
        source.start()
        val url = source.url("/socket/websocket").toString()
        val failed = CountDownLatch(1)
        lateinit var client: PhoenixClient
        try {
            instrumentation.runOnMainSync {
                client = PhoenixClient(url, "clipboard:home", { if (it.startsWith("Disconnected")) failed.countDown() }, {}, {})
                client.start()
            }
            assertTrue(failed.await(5, TimeUnit.SECONDS))
            instrumentation.runOnMainSync { client.stop() }
            assertEquals(0, destination.requestCount)
        } finally {
            instrumentation.runOnMainSync { client.dispose() }
            source.close()
            destination.close()
        }
    }

    fun testActivityAcceptsShareWithoutAutomaticSend() {
        val intent = Intent(instrumentation.targetContext, MainActivity::class.java)
            .setAction(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, "012345")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val activity = instrumentation.startActivitySync(intent)
        instrumentation.waitForIdleSync()
        assertNull(activity.intent.getCharSequenceExtra(Intent.EXTRA_TEXT))
        instrumentation.runOnMainSync { activity.finish() }
    }
}
