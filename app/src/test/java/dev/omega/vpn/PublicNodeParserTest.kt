package dev.omega.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class PublicNodeParserTest {
    private val valid = "vless://00000000-0000-4000-8000-000000000001@8.8.8.8:443" +
        "?encryption=none&security=reality&type=tcp&sni=www.example.org" +
        "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd&fp=chrome" +
        "&flow=xtls-rprx-vision#Demo"

    @Test fun parsesBase64SubscriptionWithoutManualKeys() {
        val body = (valid + "\n" + "trojan://example\n" + valid).toByteArray(Charsets.UTF_8)
        val encoded = Base64.getEncoder().encodeToString(body)
        val servers = PublicNodeParser.parse(encoded)
        assertEquals(1, servers.size)
        assertEquals("8.8.8.8", servers.single().host)
        assertEquals(443, servers.single().port)
    }

    @Test fun parsesRawListAndSkipsUnsupportedConfigs() {
        val body = valid + "\n" + valid.replace("type=tcp","type=ws") +
            "\n" + valid.replace("security=reality","security=tls")
        assertEquals(1, PublicNodeParser.parse(body).size)
    }

    @Test fun handlesEmptyContent() {
        assertTrue(PublicNodeParser.parse("").isEmpty())
    }

    @Test fun rejectsUnsupportedFormat() {
        assertThrows(IllegalArgumentException::class.java) {
            PublicNodeParser.parse("invalid subscription payload!")
        }
    }

    @Test fun refusesOversizedInput() {
        assertThrows(IllegalArgumentException::class.java) {
            PublicNodeParser.parse("A".repeat(2_000_001))
        }
    }

    @Test fun preventsHugeCatalogFromOverloadingUi() {
        val body = (1..180).joinToString("\n") { n ->
            valid.replace("8.8.8.8", "8.8.10.${n}")
        }
        assertEquals(120, PublicNodeParser.parse(body).size)
    }
}

