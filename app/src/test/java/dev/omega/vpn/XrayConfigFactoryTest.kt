package dev.omega.vpn

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class XrayConfigFactoryTest {
    private val link = "vless://00000000-0000-4000-8000-000000000001@vpn.example.org:443" +
        "?encryption=none&security=reality&type=tcp&sni=www.example.org" +
        "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd&fp=chrome" +
        "&flow=xtls-rprx-vision#Sample"

    @Test fun nativeTunOnlyRoutesThroughProxy() {
        val config = XrayConfigFactory.build(VlessProfile.parse(link))
        val obj = JSONObject(config)
        val inbounds = obj.getJSONArray("inbounds")
        val outbounds = obj.getJSONArray("outbounds")
        assertEquals(1,inbounds.length())
        assertEquals("tun",inbounds.getJSONObject(0).getString("protocol"))
        assertEquals(1,outbounds.length())
        assertEquals("vless",outbounds.getJSONObject(0).getString("protocol"))
        assertEquals("proxy",obj.getJSONObject("routing").getJSONArray("rules")
            .getJSONObject(0).getString("outboundTag"))
        assertFalse("No direct fallback permitted",config.contains("\"freedom\""))
        assertEquals("reality",outbounds.getJSONObject(0).getJSONObject("streamSettings")
            .getString("security"))
    }
}
