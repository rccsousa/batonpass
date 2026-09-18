package co.subvisual.batonpass

import java.net.URI

data class Enrollment(val host: String, val group: String, val sender: Long,
                      val epoch: Long, val key: ByteArray) {
    val topic get() = "clipboard:$group"
    val url get() = "ws://$host/socket/websocket?vsn=2.0.0"

    fun validate() {
        require(key.size == 32) { "Group key must contain 64 hexadecimal characters." }
        require(sender in 0..0xffffffffL && epoch in 0..0xffffffffL) { "Sender and epoch must be uint32 values." }
        require(group.matches(Regex("[A-Za-z0-9_-]{1,64}"))) { "Group: use 1–64 letters, digits, underscores or hyphens." }
        val uri = URI(url)
        require(uri.rawAuthority == host && uri.userInfo == null && uri.port in 1..65535 &&
            uri.rawPath == "/socket/websocket" && uri.rawQuery == "vsn=2.0.0" && uri.fragment == null)
        // Keep plaintext HTTP/WebSocket metadata confined to a literal Tailscale IPv4.
        // No DNS resolution, public endpoints, proxy URLs, or userinfo are accepted.
        val ip = uri.host?.split('.')?.map { part ->
            require(part.matches(Regex("0|[1-9][0-9]{0,2}")))
            part.toInt().also { require(it in 0..255) }
        } ?: error("Relay must be a Tailscale IPv4 address and port.")
        require(ip.size == 4 && ip[0] == 100 && ip[1] in 64..127) {
            "Use the relay's Tailscale IPv4 and port, e.g. 100.64.0.10:4000."
        }
    }

    fun sameIdentity(other: Enrollment) = group == other.group && sender == other.sender &&
        epoch == other.epoch && key.contentEquals(other.key)
}
