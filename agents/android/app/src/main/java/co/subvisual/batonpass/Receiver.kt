package co.subvisual.batonpass

data class ReplayState(val counter: Long, val wall: Long, val entries: Map<String, Long>,
                       val lastReceivedHash: String? = null)
data class ReplayAnchor(val counter: Long, val tripped: Boolean)

interface ReplayStore {
    fun state(): ReplayState
    fun anchor(): ReplayAnchor
    fun writeState(state: ReplayState)
    fun writeAnchor(anchor: ReplayAnchor)
}

/** All calls are serialized by the activity. Persistence precedes plaintext delivery. */
class Receiver(private val key: ByteArray, private val epoch: Long, private val store: ReplayStore,
               private val wall: () -> Long, private val monotonic: () -> Long) {
    private var state = ReplayState(0, 0, emptyMap())
    private var lastWall = wall()
    private var lastMono = monotonic()
    var tripped = true
        private set

    init {
        try {
            state = store.state()
            val anchor = store.anchor()
            require(!anchor.tripped && anchor.counter == state.counter)
            require(state.counter >= 0 && state.wall in 0..lastWall && state.entries.size <= 4096)
            require(state.entries.values.all { it >= 0 })
            tripped = false
        } catch (_: Exception) { trip() }
    }

    private fun trip() {
        tripped = true
        try {
            val highWater = maxOf(state.counter, runCatching { store.anchor().counter }.getOrDefault(0))
            store.writeAnchor(ReplayAnchor(highWater, true))
        } catch (_: Exception) { }
    }

    fun checkpoint() {
        check(!tripped) { "Receiver paused; correct the clock and explicitly resume." }
        val now = wall()
        val mono = monotonic()
        if (now < lastWall || now < state.wall || mono < lastMono ||
            kotlin.math.abs((now - lastWall) - (mono - lastMono)) > 2_000) {
            trip()
            error("Clock changed; correct it and explicitly resume.")
        }
        lastWall = now
        lastMono = mono
        try {
            state = state.copy(wall = now)
            store.writeState(state)
        } catch (_: Exception) { trip(); error("Replay storage unavailable.") }
    }

    fun accept(frame: ByteArray): String {
        check(!tripped)
        val header = Envelope.header(frame)
        require(header.epoch == epoch)
        val plaintext = Envelope.open(key, frame)
        checkpoint()
        val now = lastWall
        // Negative signed values represent uint64 timestamps above Long.MAX_VALUE.
        require(header.timestamp >= 0 && header.timestamp <= now + 60_000 &&
            header.timestamp >= now - 60_000)
        val id = "${header.epoch}:${header.sender}:${header.eventId}"
        // Freshness includes the exact boundary, so expiration must be strictly earlier.
        val live = state.entries.filterValues { it >= now }.toMutableMap()
        require(id !in live && live.size < 4096)
        val text = Envelope.text(plaintext)
        live[id] = maxOf(now, header.timestamp) + 60_000
        try {
            val next = ReplayState(Math.addExact(state.counter, 1), now, live, digest(text))
            store.writeAnchor(ReplayAnchor(next.counter, false))
            store.writeState(next)
            state = next
        } catch (_: Exception) { trip(); error("Replay storage unavailable.") }
        return text
    }

    fun wasReceived(text: String): Boolean = state.lastReceivedHash == digest(text)

    private fun digest(text: String) = java.security.MessageDigest.getInstance("SHA-256")
        .digest(text.toByteArray(Charsets.UTF_8)).hex()

    /** Operator-only recovery. Never called automatically after a load failure. */
    fun resumeAfterClockCorrection() {
        val counter = maxOf(state.counter, runCatching { store.anchor().counter }.getOrDefault(0))
        val next = ReplayState(counter, wall(), emptyMap())
        tripped = true
        store.writeAnchor(ReplayAnchor(counter, true))
        store.writeState(next)
        store.writeAnchor(ReplayAnchor(counter, false))
        state = next
        lastWall = next.wall
        lastMono = monotonic()
        tripped = false
    }
}
