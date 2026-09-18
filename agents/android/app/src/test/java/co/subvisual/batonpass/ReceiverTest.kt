package co.subvisual.batonpass

import org.junit.Assert.*
import org.junit.Test

class ReceiverTest {
    private class MemoryStore : ReplayStore {
        var snapshot = ReplayState(0, 1_000_000, emptyMap())
        var mark = ReplayAnchor(0, false)
        var missing = false
        var failWrite = false
        var failAcceptance = false
        override fun state(): ReplayState { check(!missing); return snapshot }
        override fun anchor() = mark
        override fun writeState(state: ReplayState) {
            check(!failWrite && !(failAcceptance && state.counter > snapshot.counter))
            snapshot = state
        }
        override fun writeAnchor(anchor: ReplayAnchor) { mark = anchor }
    }
    private val key = ByteArray(32) { it.toByte() }
    private var now = 1_000_000L
    private var mono = 10_000L
    private fun advance(ms: Long) { now += ms; mono += ms }
    private fun frame(time: Long = now) = Envelope.seal(key, 1, 3, "012345", time)
    private fun receiver(store: MemoryStore) = Receiver(key, 1, store, { now }, { mono })

    @Test fun persistsBeforeReturningAndRejectsAcrossRestart() {
        val store = MemoryStore()
        val f = frame()
        assertEquals("012345", receiver(store).accept(f))
        assertEquals(1, store.snapshot.counter)
        assertEquals(store.mark.counter, store.snapshot.counter)
        assertThrows(Exception::class.java) { receiver(store).accept(f) }
    }

    @Test fun aheadTimestampRetainedThroughInclusiveFreshnessBoundary() {
        val store = MemoryStore()
        val rx = receiver(store)
        val f = frame(now + 45_000)
        rx.accept(f)
        advance(105_000)
        assertThrows(Exception::class.java) { rx.accept(f) }
        assertEquals(1, store.snapshot.counter)
    }

    @Test fun fullCacheDoesNotEvictLiveEntries() {
        val store = MemoryStore()
        store.snapshot = store.snapshot.copy(entries = (1..4096).associate { "$it" to now + 60_000 })
        assertThrows(Exception::class.java) { receiver(store).accept(frame()) }
        assertEquals(4096, store.snapshot.entries.size)
    }

    @Test fun missingOrRolledBackStateAndStickyTripFailClosed() {
        for (store in listOf(MemoryStore().apply { missing = true },
            MemoryStore().apply { mark = ReplayAnchor(1, false) },
            MemoryStore().apply { mark = ReplayAnchor(0, true) })) {
            val rx = receiver(store)
            assertTrue(rx.tripped)
            assertThrows(Exception::class.java) { rx.accept(frame()) }
            assertTrue(store.mark.tripped)
        }
    }

    @Test fun storageFailureNeverReturnsPlaintext() {
        val store = MemoryStore()
        val rx = receiver(store)
        store.failWrite = true
        assertThrows(Exception::class.java) { rx.accept(frame()) }
        assertTrue(rx.tripped)
        assertTrue(receiver(store).tripped)
    }

    @Test fun partialAcceptanceCommitKeepsCounterHighWaterAndTrips() {
        val store = MemoryStore()
        val rx = receiver(store)
        store.failAcceptance = true
        assertThrows(Exception::class.java) { rx.accept(frame()) }
        assertEquals(1L, store.mark.counter)
        assertEquals(0L, store.snapshot.counter)
        assertTrue(store.mark.tripped)
        assertTrue(receiver(store).tripped)
        store.failAcceptance = false
        rx.resumeAfterClockCorrection()
        assertEquals(1L, store.snapshot.counter)
    }

    @Test fun backwardAndForwardClockJumpsTripUntilExplicitRecovery() {
        for (jump in listOf(-1L, 20_000L)) {
            val store = MemoryStore().apply { snapshot = snapshot.copy(wall = now) }
            val rx = receiver(store)
            now += jump
            assertThrows(Exception::class.java) { rx.checkpoint() }
            assertTrue(rx.tripped)
            assertTrue(receiver(store).tripped)
            rx.resumeAfterClockCorrection()
            assertFalse(rx.tripped)
            assertEquals("012345", rx.accept(frame()))
        }
    }

    @Test fun invalidAuthenticationEpochAndTimestampDoNotConsumeCache() {
        val store = MemoryStore()
        val rx = receiver(store)
        val badTag = frame().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        for (f in listOf(badTag, Envelope.seal(key, 2, 3, "x", now), frame(now + 60_001),
            frame(now - 60_001), frame(-1))) {
            assertThrows(Exception::class.java) { rx.accept(f) }
        }
        assertEquals(0, store.snapshot.counter)
        assertFalse(rx.tripped)
    }
}
