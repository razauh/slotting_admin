package com.slotting.admin.gameprovider

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import java.util.UUID

enum class FairnessEnvelopeClassification {
    ENCRYPTED,
    LEGACY_PLAINTEXT,
    UNCLASSIFIABLE,
    MISSING_IDENTITY,
}

data class FairnessEnvelopeInventoryRow(
    val commitmentId: UUID?,
    val tenantId: String?,
    val gameId: String?,
    val roundId: String?,
    val classification: FairnessEnvelopeClassification,
    val reason: String,
)

class FairnessEnvelopeMigrationException(
    val affectedIdentities: List<String>,
    message: String,
) : RuntimeException(message)

@Component
class FairnessEnvelopeMigrationDiagnostic(
    private val jdbc: JdbcTemplate,
) {
    private val plaintextPattern = Regex("^[0-9a-fA-F]{64}$")

    fun inventory(): List<FairnessEnvelopeInventoryRow> {
        val sql = """
            select commitment_id, tenant_id, game_id, round_id, encrypted_secret_seed,
                   secret_nonce, secret_key_id, secret_key_version, secret_format_version
            from game_fairness_commitment
            order by tenant_id, game_id, round_id
        """.trimIndent()
        return jdbc.query(sql) { rs, _ ->
            val commitmentId = runCatching { rs.getObject("commitment_id", UUID::class.java) }.getOrNull()
            val tenantId = rs.getString("tenant_id")
            val gameId = rs.getString("game_id")
            val roundId = rs.getString("round_id")
            val stored = rs.getString("encrypted_secret_seed")
            val nonce = rs.getString("secret_nonce")
            val keyId = rs.getString("secret_key_id")
            val keyVersion = rs.getObject("secret_key_version", Integer::class.java)
            val formatVersion = rs.getObject("secret_format_version", Integer::class.java)

            val (classification, reason) = when {
                commitmentId == null || tenantId.isNullOrBlank() || gameId.isNullOrBlank() || roundId.isNullOrBlank() ->
                    FairnessEnvelopeClassification.MISSING_IDENTITY to "missing tenant/game/round/commitment identity"
                nonce.isNullOrBlank() && stored != null && plaintextPattern.matches(stored) ->
                    FairnessEnvelopeClassification.LEGACY_PLAINTEXT to "pre-envelope plaintext seed at rest"
                nonce.isNullOrBlank() ->
                    FairnessEnvelopeClassification.UNCLASSIFIABLE to "no envelope metadata and seed is not a canonical plaintext seed"
                keyId.isNullOrBlank() || keyVersion == null || formatVersion == null ->
                    FairnessEnvelopeClassification.UNCLASSIFIABLE to "envelope metadata incomplete"
                else -> FairnessEnvelopeClassification.ENCRYPTED to "authenticated envelope present"
            }

            FairnessEnvelopeInventoryRow(
                commitmentId = commitmentId,
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                classification = classification,
                reason = reason,
            )
        }
    }

    fun assertSafeToProceed() {
        val blocking = inventory().filter {
            it.classification == FairnessEnvelopeClassification.LEGACY_PLAINTEXT ||
                it.classification == FairnessEnvelopeClassification.UNCLASSIFIABLE ||
                it.classification == FairnessEnvelopeClassification.MISSING_IDENTITY
        }
        if (blocking.isNotEmpty()) {
            val identities = blocking.map { "${it.tenantId}/${it.gameId}/${it.roundId}[${it.classification}]" }
            throw FairnessEnvelopeMigrationException(
                affectedIdentities = identities,
                message = "Fairness envelope pre-check rejected ${identities.size} unclassified commitment row(s): $identities",
            )
        }
    }
}
