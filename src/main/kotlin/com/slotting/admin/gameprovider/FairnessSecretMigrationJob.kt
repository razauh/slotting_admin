package com.slotting.admin.gameprovider

import com.slotting.admin.secret.DecryptionTamperException
import org.springframework.jdbc.core.JdbcTemplate
import java.security.MessageDigest
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.util.UUID

data class FairnessMigrationFailure(
    val commitmentId: UUID,
    val tenantId: String,
    val gameId: String,
    val roundId: String,
    val reason: String,
)

data class FairnessSecretMigrationResult(
    val processedCount: Int,
    val encryptedCount: Int,
    val skippedCount: Int,
    val failures: List<FairnessMigrationFailure>,
    val remainingCount: Int,
    val runId: UUID,
    val completed: Boolean,
)

class FairnessSecretMigrationJob(
    private val jdbc: JdbcTemplate,
    private val store: FairnessEvidenceStore,
    private val envelope: FairnessSeedEnvelope,
    private val clock: Clock = Clock.systemUTC(),
    private val beforeReplace: (RoundCommitmentRecord) -> Unit = {},
) {
    private val canonicalSeed = Regex("^[0-9a-fA-F]{64}$")

    fun remainingCount(tenantId: String): Int =
        store.findAllCommitments(tenantId).count { needsEnvelope(it) }

    fun remainingKeyReferences(tenantId: String, keyVersion: Int): Int =
        store.findAllCommitments(tenantId).count {
            !it.secretNonce.isNullOrBlank() && it.secretKeyVersion == keyVersion && it.secretKeyId == envelope.keyId
        }

    fun canRetireKey(tenantId: String, keyVersion: Int): Boolean =
        remainingKeyReferences(tenantId, keyVersion) == 0

    fun migrate(tenantId: String): FairnessSecretMigrationResult {
        val runId = UUID.randomUUID()
        val startedAt = clock.instant()
        jdbc.update(
            "insert into fairness_secret_migration_run (run_id, tenant_id, started_at, status) values (?, ?, ?, 'RUNNING')",
            runId, tenantId, Timestamp.from(startedAt),
        )

        var processed = 0
        var encrypted = 0
        var skipped = 0
        val failures = mutableListOf<FairnessMigrationFailure>()

        try {
            val candidates = store.findAllCommitments(tenantId)
                .filter { needsEnvelope(it) }
                .sortedWith(compareBy({ it.status == RoundCommitmentStatus.REVEALED }, { it.commitmentId }))

            for (candidate in candidates) {
                processed++
                if (!needsEnvelope(candidate)) {
                    skipped++
                    continue
                }

                val seed = resolvePlaintext(candidate, failures) ?: continue
                val sealed = envelope.seal(candidate.tenantId, candidate.gameId, candidate.roundId, candidate.commitmentId.toString(), seed)
                val roundTrip = envelope.open(candidate.tenantId, candidate.gameId, candidate.roundId, candidate.commitmentId.toString(), sealed)
                if (roundTrip != seed || sha256(seed) != candidate.commitmentHash) {
                    failures.add(failure(candidate, "decrypt-compare did not reproduce the committed seed"))
                    continue
                }

                beforeReplace(candidate)

                if (replaceWithCas(candidate, sealed)) {
                    encrypted++
                } else {
                    failures.add(failure(candidate, "envelope replacement lost the version compare-and-set"))
                }
            }

            val remaining = remainingCount(tenantId)
            val completed = failures.isEmpty() && remaining == 0
            finishRun(runId, completed, processed, encrypted, skipped, failures.size, remaining, startedAt)
            return FairnessSecretMigrationResult(processed, encrypted, skipped, failures.toList(), remaining, runId, completed)
        } catch (failure: RuntimeException) {
            val remaining = remainingCount(tenantId)
            finishRun(runId, false, processed, encrypted, skipped, failures.size, remaining, startedAt)
            throw failure
        }
    }

    private fun replaceWithCas(candidate: RoundCommitmentRecord, sealed: SealedFairnessSeed): Boolean {
        var expected = candidate.serverVersion
        var current = candidate
        repeat(MAX_CAS_ATTEMPTS) {
            val applied = store.rotateCommitmentEnvelope(
                commitmentId = current.commitmentId,
                tenantId = current.tenantId,
                expectedServerVersion = expected,
                encryptedSeed = sealed.ciphertextBase64,
                nonce = sealed.nonceBase64,
                keyId = sealed.keyId,
                keyVersion = sealed.keyVersion,
                formatVersion = sealed.formatVersion,
                updatedAt = clock.instant(),
            )
            if (applied) return true
            val fresh = store.findCommitment(current.tenantId, current.gameId, current.roundId) ?: return false
            if (!needsEnvelope(fresh)) return true
            expected = fresh.serverVersion
            current = fresh
        }
        return false
    }

    private fun resolvePlaintext(record: RoundCommitmentRecord, failures: MutableList<FairnessMigrationFailure>): String? {
        val nonce = record.secretNonce
        return if (nonce.isNullOrBlank()) {
            val seed = record.encryptedSecretSeed
            if (!canonicalSeed.matches(seed)) {
                failures.add(failure(record, "stored seed is not a canonical plaintext seed"))
                null
            } else if (sha256(seed) != record.commitmentHash) {
                failures.add(failure(record, "plaintext seed does not match the committed hash"))
                null
            } else {
                seed
            }
        } else {
            val keyId = record.secretKeyId
            val keyVersion = record.secretKeyVersion
            val formatVersion = record.secretFormatVersion
            if (keyId.isNullOrBlank() || keyVersion == null || formatVersion == null) {
                failures.add(failure(record, "envelope metadata is incomplete"))
                return null
            }
            try {
                val seed = envelope.open(
                    record.tenantId,
                    record.gameId,
                    record.roundId,
                    record.commitmentId.toString(),
                    SealedFairnessSeed(record.encryptedSecretSeed, nonce, keyId, keyVersion, formatVersion),
                )
                if (sha256(seed) != record.commitmentHash) {
                    failures.add(failure(record, "decrypted envelope does not match the committed hash"))
                    null
                } else {
                    seed
                }
            } catch (e: DecryptionTamperException) {
                failures.add(failure(record, "envelope failed authentication with the configured key"))
                null
            } catch (e: IllegalStateException) {
                failures.add(failure(record, "envelope key version is not available in the provider"))
                null
            }
        }
    }

    private fun needsEnvelope(record: RoundCommitmentRecord): Boolean =
        record.secretNonce.isNullOrBlank() ||
            record.secretKeyId.isNullOrBlank() ||
            record.secretKeyVersion == null ||
            record.secretFormatVersion == null ||
            record.secretKeyId != envelope.keyId ||
            record.secretKeyVersion != envelope.keyVersion

    private fun failure(record: RoundCommitmentRecord, reason: String): FairnessMigrationFailure =
        FairnessMigrationFailure(record.commitmentId, record.tenantId, record.gameId, record.roundId, reason)

    private fun finishRun(runId: UUID, completed: Boolean, processed: Int, encrypted: Int, skipped: Int, failures: Int, remaining: Int, startedAt: Instant) {
        jdbc.update(
            """
            update fairness_secret_migration_run
            set finished_at = ?, status = ?, processed_count = ?, encrypted_count = ?, skipped_count = ?, failure_count = ?, remaining_count = ?
            where run_id = ?
            """.trimIndent(),
            Timestamp.from(clock.instant()),
            if (completed) "COMPLETED" else "FAILED",
            processed,
            encrypted,
            skipped,
            failures,
            remaining,
            runId,
        )
    }

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    companion object {
        const val MAX_CAS_ATTEMPTS = 5
    }
}
