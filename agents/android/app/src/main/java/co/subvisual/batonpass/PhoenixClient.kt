package co.subvisual.batonpass

import android.os.Handler
import android.os.Looper
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/** Foreground-only session. Main-thread state; stale socket callbacks cannot reconnect it. */
class PhoenixClient(private val url: String, private val topic: String,
                    private val onStatus: (String) -> Unit, private val onFrame: (ByteArray) -> Unit,
                    private val onTick: () -> Unit) {
    private val handler = Handler(Looper.getMainLooper())
    private val http = OkHttpClient.Builder().connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.SECONDS).followRedirects(false).followSslRedirects(false).build()
    private var socket: WebSocket? = null
    private var stopped = true
    private var nextRef = 1L
    private var heartbeat: String? = null
    private var retry = 1L
    var joined = false
        private set

    fun start() {
        if (!stopped) return
        stopped = false
        connect()
    }

    fun stop() {
        stopped = true
        joined = false
        handler.removeCallbacksAndMessages(null)
        val old = socket
        socket = null
        old?.cancel()
    }

    fun dispose() {
        stop()
        http.dispatcher.executorService.shutdown()
        http.connectionPool.evictAll()
    }

    private fun connect() {
        if (stopped) return
        joined = false
        heartbeat = null
        nextRef = 1
        onStatus("Connecting…")
        val listener = object : WebSocketListener() {
            private fun deliver(ws: WebSocket, action: () -> Unit) {
                handler.post { if (!stopped && socket === ws) action() }
            }
            override fun onOpen(webSocket: WebSocket, response: Response) = deliver(webSocket) {
                if (!webSocket.send(control("1", "1", topic, "phx_join"))) failed()
            }
            override fun onMessage(webSocket: WebSocket, text: String) = deliver(webSocket) {
                try {
                    require(text.length <= 4096)
                    val message = JSONArray(text)
                    require(message.length() == 5)
                    val event = message.getString(3)
                    if (message.getString(2) == topic && event in listOf("phx_error", "phx_close")) {
                        failed(); return@deliver
                    }
                    if (event != "phx_reply") return@deliver
                    val ref = message.optString(1)
                    val ok = message.getJSONObject(4).optString("status") == "ok"
                    if (ref == "1" && message.optString(0) == "1" && message.getString(2) == topic) {
                        if (!ok) { failed(); return@deliver }
                        if (!joined) {
                            joined = true
                            retry = 1
                            onStatus("Connected · receiving while open")
                            scheduleHeartbeat(webSocket)
                        }
                    } else if (ref == heartbeat && message.getString(2) == "phoenix" && ok) {
                        heartbeat = null
                    }
                } catch (_: Exception) { failed() }
            }
            override fun onMessage(webSocket: WebSocket, bytes: ByteString) = deliver(webSocket) {
                try {
                    require(bytes.size <= Envelope.MAX_FRAME + 1025)
                    val message = PhoenixWire.decode(bytes.toByteArray())
                    if (joined && message.topic == topic && message.event == "frame" &&
                        (message.kind == 2 || (message.kind == 0 && message.join == "1"))) {
                        onFrame(message.payload)
                    }
                } catch (_: Exception) { failed() }
            }
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) =
                deliver(webSocket) { failed() }
            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) =
                deliver(webSocket) { failed() }
            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) =
                deliver(webSocket) { failed() }
        }
        val fresh = http.newWebSocket(Request.Builder().url(url).build(), listener)
        socket = fresh
        handler.postDelayed({ if (socket === fresh && !joined) failed() }, 10_000)
    }

    private fun scheduleHeartbeat(ws: WebSocket) {
        handler.postDelayed({
            if (socket === ws && joined && !stopped) {
                if (heartbeat != null) { failed(); return@postDelayed }
                onTick()
                val ref = (++nextRef).toString()
                heartbeat = ref
                if (!ws.send(control(null, ref, "phoenix", "heartbeat"))) failed()
                else scheduleHeartbeat(ws)
            }
        }, 15_000)
    }

    private fun failed() {
        if (stopped) return
        val old = socket ?: return
        socket = null
        joined = false
        old.cancel()
        handler.removeCallbacksAndMessages(null)
        onStatus("Disconnected · check Tailscale and relay allowlist · retrying")
        handler.postDelayed({ connect() }, retry * 1000)
        retry = minOf(retry * 2, 30)
    }

    /** True means queued to the socket, not acknowledged or delivered by the relay. */
    fun send(frame: ByteArray): Boolean {
        if (!joined) return false
        val ws = socket ?: return false
        if (ws.queueSize() > 0) return false // no unbounded queue or hidden offline sends
        val queued = ws.send(PhoenixWire.push("1", (++nextRef).toString(), topic, frame).toByteString())
        if (!queued) failed()
        return queued
    }

    private fun control(join: String?, ref: String, topic: String, event: String) = JSONArray()
        .put(join ?: JSONObject.NULL).put(ref).put(topic).put(event).put(JSONObject()).toString()
}
