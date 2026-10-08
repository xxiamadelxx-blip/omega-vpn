package dev.omega.vpn

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Public and attribution-preserving source. No paid provider endpoints, tokens or API keys.
 * Read over HTTPS only, after the user taps "Find free VPN".
 */
object FreeNodeSource {
    const val NAME = "Au1rxx / Free VPN Subscriptions"
    const val URL = "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt"
    const val LICENSE = "MIT (list publisher; individual node trust and terms are not guaranteed)"
}

data class PublicNode(val uri: String, val host: String, val port: Int)

/** Strictly bounded decoder shared by Android network client and JVM unit tests. */
object PublicNodeParser {
    private const val MAX_FEED_CHARS = 2_000_000
    private const val MAX_NODES = 120
    private const val MAX_LINES = 5000

    fun parse(input: String): List<PublicNode> {
        require(input.length <= MAX_FEED_CHARS) { "Слишком большой список серверов" }
        val trimmed = input.trim()
        if (trimmed.isEmpty()) return emptyList()

        val decoded = if (trimmed.contains("vless://", ignoreCase = true)) trimmed else {
            val compact = trimmed.filterNot(Char::isWhitespace)
            require(compact.length <= MAX_FEED_CHARS) { "Слишком большой список серверов" }
            val plain = try {
                String(Base64.getDecoder().decode(compact), StandardCharsets.UTF_8)
            } catch (_: IllegalArgumentException) {
                throw IllegalArgumentException("Неподдерживаемый формат подписки")
            }
            require(plain.length <= MAX_FEED_CHARS) { "Слишком большой список серверов" }
            plain
        }

        val seen = HashSet<String>()
        val result = ArrayList<PublicNode>()
        // Avoid processing unbounded untrusted input even if individual entries are tiny.
        for (line in decoded.lineSequence().take(MAX_LINES)) {
            if (result.size == MAX_NODES) break
            val uri = line.trim()
            if (!uri.startsWith("vless://", ignoreCase = true)) continue
            val profile = try { VlessProfile.parse(uri) } catch (_: Exception) { continue }
            val unique = listOf(profile.host, profile.port, profile.uuid, profile.publicKey).joinToString("|")
            if (!seen.add(unique)) continue
            result.add(PublicNode(uri, profile.host, profile.port))
        }
        return result
    }
}

class FreeNodeRepository {
    private val maxDownloadBytes = 1_500_000

    /** Must be called on a background dispatcher; does not write keys to disk. */
    fun load(): List<PublicNode> {
        val connection = URL(FreeNodeSource.URL).openConnection() as HttpURLConnection
        connection.connectTimeout = 10_000
        connection.readTimeout = 15_000
        connection.instanceFollowRedirects = false
        connection.useCaches = false
        connection.setRequestProperty("Accept", "text/plain")
        try {
            if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                throw IOException("Не удалось обновить каталог: HTTP ${connection.responseCode}")
            }
            if (connection.contentLengthLong > maxDownloadBytes) {
                throw IOException("Слишком большой ответ сервера")
            }
            val bytes = ByteArrayOutputStream()
            connection.inputStream.use { stream ->
                val chunk = ByteArray(8192)
                while (true) {
                    val count = stream.read(chunk)
                    if (count < 0) break
                    if (bytes.size() + count > maxDownloadBytes) {
                        throw IOException("Каталог превысил допустимый размер")
                    }
                    bytes.write(chunk, 0, count)
                }
            }
            val nodes = PublicNodeParser.parse(bytes.toString(StandardCharsets.UTF_8.name()))
            if (nodes.isEmpty()) throw IOException("В каталоге нет совместимых VLESS/Reality серверов")
            return nodes
        } finally {
            connection.disconnect()
        }
    }
}
