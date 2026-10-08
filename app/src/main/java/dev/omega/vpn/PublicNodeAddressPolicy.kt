package dev.omega.vpn

/**
 * Strict policy for anonymously published VPN endpoints.
 *
 * Only canonical, globally routable IPv4 literals are accepted from this
 * public catalogue. No DNS lookups occur here, avoiding a feed-controlled
 * hostname resolving to an internal address or Android device service.
 * This filter cannot establish who owns a public IP, or whether it is safe.
 */
object PublicNodeAddressPolicy {
    fun isAllowed(host: String): Boolean {
        val octets = host.split('.')
        if (octets.size != 4) return false
        val bytes = IntArray(4)
        for (i in 0..3) {
            val part = octets[i]
            if (part.isEmpty() || part.length > 3 || !part.all { it in '0'..'9' }) return false
            val value = part.toIntOrNull() ?: return false
            if (value !in 0..255 || part != value.toString()) return false
            bytes[i] = value
        }
        val a = bytes[0]
        val b = bytes[1]
        val c = bytes[2]
        return when {
            a == 0 || a == 10 || a == 127 || a >= 224 -> false
            a == 100 && b in 64..127 -> false // carrier-grade NAT
            a == 169 && b == 254 -> false // link local / metadata
            a == 172 && b in 16..31 -> false
            a == 192 && b == 168 -> false
            a == 192 && b == 0 && (c == 0 || c == 2) -> false
            a == 192 && b == 88 && c == 99 -> false
            a == 198 && b in 18..19 -> false // benchmarking
            a == 198 && b == 51 && c == 100 -> false
            a == 203 && b == 0 && c == 113 -> false
            else -> true
        }
    }
}
