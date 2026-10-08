package dev.omega.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class BuildStageTest {
    @Test fun stageDoesNotClaimDeviceAcceptance() {
        assertEquals("M2-development", BuildStage.NAME)
        assertFalse("M2 must not claim a verified working VPN", BuildStage.VPN_ENGINE_READY)
    }
}
