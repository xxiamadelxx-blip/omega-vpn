package dev.omega.vpn

import java.net.URI
import java.net.URLDecoder
import java.util.UUID

/** M2 subset: VLESS / TCP / Reality only. No private credentials in logs. */
data class VlessProfile(
    val host: String, val port: Int, val uuid: String, val sni: String,
    val publicKey: String, val shortId: String, val fingerprint: String,
    val flow: String, val spiderX: String
) {
    companion object {
        fun parse(raw: String): VlessProfile {
            val text = raw.trim()
            require(text.length in 30..4096 && text.startsWith("vless://", true)) { "Требуется VLESS-ссылка" }
            val uri = runCatching { URI(text) }.getOrElse { throw IllegalArgumentException("Неверный адрес") }
            val id = uri.rawUserInfo ?: throw IllegalArgumentException("Нет UUID")
            require(id.matches(Regex("[a-fA-F0-9-]{36}")) && runCatching { UUID.fromString(id) }.isSuccess) { "Неверный UUID" }
            val host = uri.host ?: throw IllegalArgumentException("Нет адреса сервера")
            require(host.isNotBlank() && host.length <= 253 && uri.port in 1..65535) { "Неверный сервер или порт" }
            val q = mutableMapOf<String, String>()
            (uri.rawQuery ?: "").split("&").filter { it.isNotBlank() }.forEach {
                val kv = it.split("=", limit = 2)
                val key = URLDecoder.decode(kv[0], "UTF-8").lowercase()
                q[key] = URLDecoder.decode(kv.getOrElse(1) { "" }, "UTF-8")
            }
            fun param(key: String) = q[key].orEmpty()
            require(param("security").equals("reality", true)) { "Поддерживается только Reality" }
            require(param("type").ifEmpty { "tcp" }.equals("tcp", true)) { "Поддерживается только TCP" }
            require(param("encryption").ifEmpty { "none" } == "none") { "Неподдерживаемое шифрование" }
            val sni = param("sni")
            require(sni.matches(Regex("[A-Za-z0-9.-]{1,253}"))) { "Не указан корректный SNI" }
            val pbk = param("pbk")
            require(pbk.matches(Regex("[a-zA-Z0-9_-]{43}"))) { "Неверный публичный ключ Reality" }
            val sid = param("sid")
            require(sid.matches(Regex("[a-fA-F0-9]{0,16}")) && sid.length % 2 == 0) { "Неверный shortId" }
            val fp = param("fp").ifEmpty { "chrome" }
            require(fp in setOf("chrome","firefox","edge","safari","ios","android","random","randomized")) { "Неверный fingerprint" }
            val flow = param("flow")
            require(flow.isEmpty() || flow == "xtls-rprx-vision") { "Неподдерживаемый flow" }
            val spider = param("spx").ifEmpty { "/" }
            require(spider.startsWith("/") && spider.length <= 200) { "Неверный spiderX" }
            return VlessProfile(host,uri.port,id,sni,pbk,sid,fp,flow,spider)
        }
    }
}
