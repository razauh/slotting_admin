package com.slotting.admin.withdrawal

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.time.Instant

class DeviceTravelVelocityPolicyTest {
    @Test
    fun distantLocationsWithinAnImpossibleWindowRequireStepUp() {
        assertTrue(
            DeviceTravelVelocityPolicy.requiresStepUp(
                40.7128,
                -74.0060,
                Instant.parse("2026-10-14T10:00:00Z"),
                51.5072,
                -0.1276,
                Instant.parse("2026-10-14T15:00:00Z"),
                900.0,
            )
        )
    }

    @Test
    fun sameLocationDoesNotRequireStepUpWhenOnlyTheNetworkAddressChanges() {
        assertFalse(
            DeviceTravelVelocityPolicy.requiresStepUp(
                24.8607,
                67.0011,
                Instant.parse("2026-10-14T10:00:00Z"),
                24.8607,
                67.0011,
                Instant.parse("2026-10-14T10:01:00Z"),
                900.0,
            )
        )
    }

    @Test
    fun routineTravelWithinTheConfiguredVelocityDoesNotRequireStepUp() {
        assertFalse(
            DeviceTravelVelocityPolicy.requiresStepUp(
                40.7128,
                -74.0060,
                Instant.parse("2026-10-14T10:00:00Z"),
                51.5072,
                -0.1276,
                Instant.parse("2026-10-14T18:00:00Z"),
                900.0,
            )
        )
    }
}
