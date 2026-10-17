package com.slotting.admin.config

import com.slotting.admin.gameprovider.FairnessSeedEnvelope
import com.slotting.admin.gameprovider.JdbcOutcomeFinalizationPort
import com.slotting.admin.gameprovider.OutcomeFinalizationPort
import com.slotting.admin.secret.AesGcmEnvelopeEncryptor
import com.slotting.admin.secret.LocalDevMasterKeyProvider
import com.slotting.admin.secret.MasterKeyProvider
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.core.env.Environment
import io.micrometer.core.instrument.MeterRegistry
import org.slf4j.LoggerFactory
import java.util.Base64

class EnvironmentMasterKeyProvider(
    private val keysByVersion: Map<Int, ByteArray>,
) : MasterKeyProvider {
    init {
        require(keysByVersion.isNotEmpty()) { "Fairness master key ring must not be empty" }
        keysByVersion.forEach { (version, key) ->
            require(version >= 1) { "Fairness master key version must be >= 1" }
            require(key.size == 32) { "Fairness master key v$version must be 32 bytes" }
        }
    }

    override fun getMasterKey(tenantId: String, keyVersion: Int): ByteArray =
        keysByVersion[keyVersion]
            ?: throw IllegalStateException("Fairness master key version $keyVersion is not configured")

    override fun isProductionSafe(): Boolean = true
}

@Configuration
class FairnessEnvelopeConfiguration {
    private val logger = LoggerFactory.getLogger(javaClass)

    @Bean
    fun fairnessSeedEnvelope(
        @Value("\${slotting.fairness.envelope.environment:TEST}") environment: String,
        @Value("\${slotting.fairness.envelope.key-id:}") keyId: String,
        @Value("\${slotting.fairness.envelope.key-version:1}") keyVersion: Int,
        @Value("\${slotting.fairness.envelope.key-base64:}") keyBase64: String,
        @Value("\${slotting.fairness.envelope.key-ring:}") keyRing: String = "",
        springEnvironment: Environment = org.springframework.core.env.StandardEnvironment(),
        meterRegistry: MeterRegistry? = null,
    ): FairnessSeedEnvelope {
        val profiles = springEnvironment.activeProfiles.toSet()
        val production = profiles.any { it.contains("prod", ignoreCase = true) } ||
            environment.equals("PRODUCTION", ignoreCase = true)
        val nonLocalProfile = profiles.any {
            !it.equals("local", ignoreCase = true) && !it.equals("test", ignoreCase = true)
        }
        val localOrTestEnvironment = environment.equals("LOCAL", ignoreCase = true) ||
            environment.equals("TEST", ignoreCase = true)
        val localOrTest = !production && !nonLocalProfile && localOrTestEnvironment
        val productionLike = production || !localOrTest
        val keysByVersion = LinkedHashMap<Int, ByteArray>()

        if (keyRing.isNotBlank()) {
            keyRing.split(",").forEach { entry ->
                val parts = entry.trim().split(":", limit = 2)
                require(parts.size == 2) { "Fairness key ring entry must be 'version:base64': $entry" }
                val ringVersion = parts[0].trim().toInt()
                keysByVersion[ringVersion] = Base64.getDecoder().decode(parts[1].trim())
            }
        }
        if (keyBase64.isNotBlank()) {
            keysByVersion[keyVersion] = Base64.getDecoder().decode(keyBase64)
        }

        val resolvedKeyId = keyId.ifBlank { FairnessSeedEnvelope.DEFAULT_KEY_ID }
        if (resolvedKeyId == FairnessSeedEnvelope.DEFAULT_KEY_ID && !localOrTest) {
            logger.error("fairness.envelope.devkey.refused profiles={} environment={}", profiles, environment)
            meterRegistry?.counter("fairness_envelope_fail_closed_total", "reason", "dev_key_outside_local_test")?.increment()
            throw IllegalStateException("Fairness development key is forbidden outside local and test environments")
        }

        if (productionLike) {
            require(keyId.isNotBlank()) { "Fairness master key id must be configured in production" }
            require(keysByVersion.containsKey(keyVersion)) {
                "Fairness master key material for the active version $keyVersion must be configured in production"
            }
        }

        if (keysByVersion.isEmpty()) {
            return FairnessSeedEnvelope(
                encryptor = AesGcmEnvelopeEncryptor(LocalDevMasterKeyProvider(), environment = "TEST"),
                keyId = resolvedKeyId,
                keyVersion = keyVersion,
            )
        }

        return FairnessSeedEnvelope(
            encryptor = AesGcmEnvelopeEncryptor(
                masterKeyProvider = EnvironmentMasterKeyProvider(keysByVersion),
                environment = if (productionLike) "PRODUCTION" else "TEST",
            ),
            keyId = resolvedKeyId,
            keyVersion = keyVersion,
        )
    }

    @Bean
    @ConditionalOnProperty(
        prefix = "slotting.fairness.reveal",
        name = ["require-finalized"],
        havingValue = "true",
        matchIfMissing = false,
    )
    fun outcomeFinalizationPort(jdbcTemplate: JdbcTemplate): OutcomeFinalizationPort =
        JdbcOutcomeFinalizationPort(jdbcTemplate)
}
