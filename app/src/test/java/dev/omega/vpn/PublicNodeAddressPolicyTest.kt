package dev.omega.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Test

class PublicNodeAddressPolicyTest {
    @Test fun acceptsCanonicalPublicIpv4Only() {
        assertTrue(PublicNodeAddressPolicy.isAllowed("8.8.8.8"))
        assertTrue(PublicNodeAddressPolicy.isAllowed("9.9.9.9"))
        assertTrue(PublicNodeAddressPolicy.isAllowed("1.1.1.1"))
    }

    @Test fun rejectsInternalMetadataReservedAndDNSHostnames() {
        val unsafe = listOf(
            "127.0.0.1", "10.0.0.1", "192.168.0.4", "172.16.1.2", "172.31.255.4",
            "169.254.169.254", "100.64.0.3", "0.0.0.0", "224.0.0.1", "240.1.2.3",
            "255.255.255.255", "198.18.0.1", "192.0.2.1", "198.51.100.2",
            "203.0.113.5", "192.0.0.9", "192.88.99.9", "localhost", "bad.internal",
            "myserver.example", "2130706433", "0177.0.0.1", "127.1", "::1",
            "2001:db8::1", "8.8.08.8"
        )
        unsafe.forEach { host ->
            assertFalse("Expected to reject: $host", PublicNodeAddressPolicy.isAllowed(host))
        }
    }

    @Test fun parserDoesNotImportNonPublicOrHostnameEntries() {
        fun link(host: String) =
            "vless://00000000-0000-4000-8000-000000000001@$host:443" +
                "?encryption=none&security=reality&type=tcp&sni=www.example.org" +
                "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd&fp=chrome"
        val input = listOf(link("127.0.0.1"), link("169.254.169.254"),
            link("vpn.example.org"), link("8.8.8.8")).joinToString("\n")
        val result = PublicNodeParser.parse(input)
        assertEquals(1, result.size)
        assertEquals("8.8.8.8", result[0].host)
    }
}
