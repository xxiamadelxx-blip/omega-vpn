package dev.omega.vpn

import org.json.JSONArray
import org.json.JSONObject

/** Fail closed: all TUN traffic routes only to the proxy, never 'freedom'. */
object XrayConfigFactory {
    fun build(p: VlessProfile): String {
        val user = JSONObject().put("id",p.uuid).put("encryption","none")
        if (p.flow.isNotBlank()) user.put("flow",p.flow)
        val next = JSONObject().put("address",p.host).put("port",p.port)
            .put("users",JSONArray().put(user))
        val reality = JSONObject().put("serverName",p.sni).put("publicKey",p.publicKey)
            .put("shortId",p.shortId).put("fingerprint",p.fingerprint).put("spiderX",p.spiderX)
        val outbound = JSONObject().put("tag","proxy").put("protocol","vless")
            .put("settings",JSONObject().put("vnext",JSONArray().put(next)))
            .put("streamSettings",JSONObject().put("network","tcp").put("security","reality")
                .put("realitySettings",reality))
        val tun = JSONObject().put("tag","tun").put("protocol","tun")
            .put("settings",JSONObject().put("name","xray0").put("MTU",1500))
            .put("sniffing",JSONObject().put("enabled",true)
                .put("destOverride",JSONArray().put("http").put("tls").put("quic")))
        return JSONObject().put("log",JSONObject().put("loglevel","warning"))
            .put("inbounds",JSONArray().put(tun))
            .put("outbounds",JSONArray().put(outbound))
            .put("routing",JSONObject().put("domainStrategy","AsIs")
                .put("rules",JSONArray().put(JSONObject().put("type","field")
                    .put("inboundTag",JSONArray().put("tun")).put("outboundTag","proxy"))))
            .toString()
    }
}
