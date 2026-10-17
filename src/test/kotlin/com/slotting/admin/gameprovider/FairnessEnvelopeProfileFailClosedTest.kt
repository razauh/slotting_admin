package com.slotting.admin.gameprovider

import com.slotting.admin.config.FairnessEnvelopeConfiguration
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.core.env.StandardEnvironment
import kotlin.test.assertEquals

class FairnessEnvelopeProfileFailClosedTest {
    private val configuration = FairnessEnvelopeConfiguration()

    @Test
    fun productionProfileFailsWhenKeyMaterialIsMissingRegardlessOfEnvelopeEnvironment() {
        val environment = StandardEnvironment().apply { setActiveProfiles("production") }
        assertThrows<IllegalStateException> {
            configuration.fairnessSeedEnvelope(
                environment = "STAGING",
                keyId = "",
                keyVersion = 1,
                keyBase64 = "",
                springEnvironment = environment,
                meterRegistry = SimpleMeterRegistry(),
            )
        }
    }

    @Test
    fun devKeyIsRejectedAndCountedOutsideLocalAndTest() {
        val environment = StandardEnvironment().apply { setActiveProfiles("staging") }
        val meters = SimpleMeterRegistry()
        assertThrows<IllegalStateException> {
            configuration.fairnessSeedEnvelope(
                environment = "STAGING",
                keyId = "",
                keyVersion = 1,
                keyBase64 = "",
                springEnvironment = environment,
                meterRegistry = meters,
            )
        }
        assertEquals(1.0, meters.get("fairness_envelope_fail_closed_total").tag("reason", "dev_key_outside_local_test").counter().count())
    }

    @Test
    fun testEnvelopeNameDoesNotOverrideStagingProfile() {
        val environment = StandardEnvironment().apply { setActiveProfiles("staging") }
        assertThrows<IllegalStateException> {
            configuration.fairnessSeedEnvelope(
                environment = "TEST",
                keyId = "",
                keyVersion = 1,
                keyBase64 = "",
                springEnvironment = environment,
                meterRegistry = SimpleMeterRegistry(),
            )
        }
    }

    @Test
    fun productionEnvelopeNameOverridesLocalProfile() {
        val environment = StandardEnvironment().apply { setActiveProfiles("local") }
        assertThrows<IllegalStateException> {
            configuration.fairnessSeedEnvelope(
                environment = "PRODUCTION",
                keyId = "",
                keyVersion = 1,
                keyBase64 = "",
                springEnvironment = environment,
                meterRegistry = SimpleMeterRegistry(),
            )
        }
    }

    @Test
    fun explicitDevelopmentKeyRemainsAvailableInTestProfile() {
        val environment = StandardEnvironment().apply { setActiveProfiles("test") }
        val envelope = configuration.fairnessSeedEnvelope(
            environment = "TEST",
            keyId = "",
            keyVersion = 1,
            keyBase64 = "",
            springEnvironment = environment,
            meterRegistry = SimpleMeterRegistry(),
        )
        assertEquals(FairnessSeedEnvelope.DEFAULT_KEY_ID, envelope.keyId)
    }
}
