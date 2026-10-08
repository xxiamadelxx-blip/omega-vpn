package dev.omega.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class BuildStageTest {
    @Test
    fun stageCannotPretendToHaveVPN() {
        assertEquals("M1", BuildStage.NAME)
        assertFalse("M1 must not advertise a working VPN", BuildStage.VPN_ENGINE_READY)
    }
}
