package dev.omega.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class VlessProfileTest {
    private val valid = "vless://00000000-0000-4000-8000-000000000001@vpn.example.org:443" +
        "?encryption=none&security=reality&type=tcp&sni=www.example.org" +
        "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd&fp=chrome" +
        "&flow=xtls-rprx-vision#Sample"

    @Test fun parsesTcpReality() {
        val p = VlessProfile.parse(valid)
        assertEquals("vpn.example.org",p.host)
        assertEquals(443,p.port)
        assertEquals("abcd",p.shortId)
    }
    @Test fun rejectsWsTransport() {
        assertThrows(IllegalArgumentException::class.java) {
            VlessProfile.parse(valid.replace("type=tcp","type=ws"))
        }
    }
    @Test fun rejectsTlsOnly() {
        assertThrows(IllegalArgumentException::class.java) {
            VlessProfile.parse(valid.replace("security=reality","security=tls"))
        }
    }
    @Test fun rejectsMissingPbk() {
        assertThrows(IllegalArgumentException::class.java) {
            VlessProfile.parse(valid.replace("pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","pbk="))
        }
    }
    @Test fun rejectsOddShortId() {
        assertThrows(IllegalArgumentException::class.java) {
            VlessProfile.parse(valid.replace("sid=abcd","sid=abc"))
        }
    }
}
