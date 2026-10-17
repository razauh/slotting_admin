package com.slotting.admin.gameprovider

import org.springframework.stereotype.Service
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.support.TransactionTemplate
import java.math.BigDecimal
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import org.slf4j.LoggerFactory
import io.micrometer.core.instrument.Gauge
import io.micrometer.core.instrument.MeterRegistry

/**
 * Gate to enforce TC-022: Outcome-bound fairness evidence.
 * Protected risk: "no complete outcome-bound provably-fair system, post-commit substitution"
 * Semantic contract: "Every settled round binds to pre-bet commitment and reproducible reveal evidence."
 *
 * Implements Spribe Aviator 3-Client-Seed Provably Fair consensus engine.
 */
object ProvablyFairOutcomeBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("outcome-bound fairness authority unbound")
        }
    }
}

class RoundEntropyCollector {
    private val distinctPlayers = LinkedHashMap<String, String>() // playerId -> clientSeed

    @Synchronized
    fun addPlayerBet(playerId: String, clientSeed: String?): Boolean {
        if (distinctPlayers.containsKey(playerId)) return false
        if (distinctPlayers.size < 3 && !distinctPlayers.containsKey(playerId)) {
            distinctPlayers[playerId] = clientSeed?.trim().orEmpty()
            return true
        }
        return false
    }

    @Synchronized
    fun finalizeSeeds(serverSeedHash: String, roundId: String): Triple<String, String, String> {
        val playerSeeds = distinctPlayers.values.toList()
        fun resolve(slot: Int): String {
            val idx = slot - 1
            if (idx < playerSeeds.size && playerSeeds[idx].isNotBlank()) {
                return playerSeeds[idx]
            }
            return ProvablyFairOutcomeAuthority.sha256("$serverSeedHash:fallback:$slot:$roundId")
        }
        return Triple(resolve(1), resolve(2), resolve(3))
    }
}

@Service
class ProvablyFairOutcomeAuthority(
    val store: FairnessEvidenceStore,
    private val clock: Clock = Clock.systemUTC(),
    private val envelope: FairnessSeedEnvelope,
    private val txManager: PlatformTransactionManager? = null,
    private val outcomeFinalization: OutcomeFinalizationPort? = null,
    private val meterRegistry: MeterRegistry? = null,
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val secureRandom = SecureRandom()
    private data class CollectorEntry(val collector: RoundEntropyCollector, val createdAt: Instant)
    private val entropyCollectors = ConcurrentHashMap<String, CollectorEntry>()
    private val collectorTtl = java.time.Duration.ofHours(1)
    private val maxCollectors = 10_000

    init {
        meterRegistry?.let { Gauge.builder("fairness_collector_size", entropyCollectors) { it.size.toDouble() }.register(it) }
    }

    private fun <T : Any> inTx(action: () -> T): T =
        txManager?.let { requireNotNull(TransactionTemplate(it).execute { action() }) } ?: action()

    private fun key(tenantId: String, gameId: String, roundId: String) = "$tenantId:$gameId:$roundId"

    fun publishPreBetCommitment(command: PublishCommitmentCommand): RoundCommitmentRecord {
        ProvablyFairOutcomeBinding.checkBound()
        val now = clock.instant()

        // Generate cryptographically secure 256-bit un-guessable secret serverSeed
        val seedBytes = ByteArray(32)
        secureRandom.nextBytes(seedBytes)
        val serverSeed = seedBytes.joinToString("") { "%02x".format(it) }
        val serverSeedHash = sha256(serverSeed)

        val commitmentId = UUID.randomUUID()
        val sealed = envelope.seal(
            tenantId = command.tenantId,
            gameId = command.gameId,
            roundId = command.roundId,
            commitmentId = commitmentId.toString(),
            plaintextSeed = serverSeed,
        )

        val commitment = RoundCommitmentRecord(
            commitmentId = commitmentId,
            tenantId = command.tenantId,
            gameId = command.gameId,
            roundId = command.roundId,
            authorityType = FairnessAuthorityType.INTERNAL_HMAC_SHA256,
            algorithmVersion = command.algorithmVersion,
            rulesVersion = command.rulesVersion,
            commitmentHash = serverSeedHash,
            publicSalt = command.publicSalt,
            encryptedSecretSeed = sealed.ciphertextBase64,
            committedAt = now,
            firstBetAcceptedAt = null,
            status = RoundCommitmentStatus.COMMITTED,
            serverVersion = 1L,
            createdAt = now,
            updatedAt = now,
            secretNonce = sealed.nonceBase64,
            secretKeyId = sealed.keyId,
            secretKeyVersion = sealed.keyVersion,
            secretFormatVersion = sealed.formatVersion,
        )

        return inTx {
            val existing = store.findCommitment(command.tenantId, command.gameId, command.roundId)
            if (existing != null) {
                if (existing.status != RoundCommitmentStatus.COMMITTED || existing.firstBetAcceptedAt != null) {
                    throw FairnessAuthorityException(
                        "BETTING_ACTIVE_CANNOT_COMMIT",
                        "Cannot publish or modify commitment after betting has become active for round ${command.roundId}"
                    )
                }
                throw FairnessAuthorityException(
                    "DUPLICATE_ROUND_COMMITMENT",
                    "Commitment already exists for round ${command.roundId}"
                )
            }

            evictExpiredCollectors()
            if (entropyCollectors.size >= maxCollectors) {
                entropyCollectors.entries.minByOrNull { it.value.createdAt }?.key?.let(entropyCollectors::remove)
            }
            entropyCollectors[key(command.tenantId, command.gameId, command.roundId)] = CollectorEntry(RoundEntropyCollector(), now)
            store.saveCommitment(commitment)
            store.saveAuditEvent(
                FairnessAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    roundId = command.roundId,
                    action = "PRE_BET_COMMITMENT_PUBLISHED",
                    actor = "SYSTEM_FAIRNESS_AUTHORITY",
                    detail = "Published commitment hash $serverSeedHash with salt ${command.publicSalt}",
                    occurredAt = now,
                    gameId = command.gameId,
                    commitmentId = commitmentId,
                    eventKey = "PRE_BET_COMMITMENT_PUBLISHED",
                )
            )
            commitment
        }
    }

    fun notifyBetAccepted(
        tenantId: String,
        gameId: String,
        roundId: String,
        playerId: String? = null,
        clientSeed: String? = null,
    ) {
        ProvablyFairOutcomeBinding.checkBound()
        inTx {
            val commitment = store.findCommitment(tenantId, gameId, roundId)
                ?: throw FairnessAuthorityException("COMMITMENT_NOT_FOUND", "Commitment not found for round $roundId")

            if (commitment.firstBetAcceptedAt == null) {
                val advanced = commitment.copy(
                    firstBetAcceptedAt = clock.instant(),
                    status = RoundCommitmentStatus.BETTING_ACTIVE,
                    updatedAt = clock.instant(),
                )
                if (!store.compareAndSetCommitment(advanced, commitment.serverVersion, setOf(RoundCommitmentStatus.COMMITTED))) {
                    throw FairnessAuthorityException(
                        "COMMIT_VERSION_CONFLICT",
                        "Commitment ${commitment.commitmentId} lost the first-bet transition race"
                    )
                }
            }

            if (playerId != null) {
                evictExpiredCollectors()
                val collectorEntry = entropyCollectors.computeIfAbsent(key(tenantId, gameId, roundId)) {
                    CollectorEntry(RoundEntropyCollector(), clock.instant())
                }
                val normalizedSeed = clientSeed?.trim()?.takeIf(String::isNotEmpty)
                val isNewPlayer = collectorEntry.collector.addPlayerBet(playerId, normalizedSeed)
                if (isNewPlayer && normalizedSeed != null) persistAcceptedSeed(tenantId, gameId, roundId, normalizedSeed)
            }
            Unit
        }
    }

    fun recordClientSeed(tenantId: String, gameId: String, roundId: String, playerId: String, clientSeed: String?) {
        notifyBetAccepted(tenantId, gameId, roundId, playerId, clientSeed)
    }

    fun resolveClientSeeds(
        tenantId: String,
        gameId: String,
        roundId: String,
        commitment: RoundCommitmentRecord
    ): Triple<String, String, String> {
        val collector = entropyCollectors[key(tenantId, gameId, roundId)]?.collector
        val collected = collector?.finalizeSeeds(commitment.commitmentHash, roundId) ?: Triple(
            sha256("${commitment.commitmentHash}:fallback:1:$roundId"),
            sha256("${commitment.commitmentHash}:fallback:2:$roundId"),
            sha256("${commitment.commitmentHash}:fallback:3:$roundId"),
        )
        val result = Triple(
            commitment.clientSeed1?.takeIf(String::isNotBlank) ?: collected.first,
            commitment.clientSeed2?.takeIf(String::isNotBlank) ?: collected.second,
            commitment.clientSeed3?.takeIf(String::isNotBlank) ?: collected.third,
        )
        val fallbackCount = listOf(commitment.clientSeed1, commitment.clientSeed2, commitment.clientSeed3).count { it.isNullOrBlank() }
        if (fallbackCount > 0) {
            logger.warn("fairness.fallback.mode tenantId={} gameId={} roundId={} realSeedCount={}", tenantId, gameId, roundId, 3 - fallbackCount)
            meterRegistry?.counter("fairness_fallback_rounds_total")?.increment()
        }
        return result
    }

    private fun persistAcceptedSeed(tenantId: String, gameId: String, roundId: String, seed: String) {
        repeat(MAX_DERIVE_ATTEMPTS) {
            val current = store.findCommitment(tenantId, gameId, roundId)
                ?: throw FairnessAuthorityException("COMMITMENT_NOT_FOUND", "Commitment not found for round $roundId")
            val existing = listOfNotNull(current.clientSeed1, current.clientSeed2, current.clientSeed3)
            if (seed in existing) return
            val next = current.copy(
                clientSeed1 = current.clientSeed1 ?: seed,
                clientSeed2 = if (current.clientSeed1 != null) current.clientSeed2 ?: seed else current.clientSeed2,
                clientSeed3 = if (current.clientSeed1 != null && current.clientSeed2 != null) current.clientSeed3 ?: seed else current.clientSeed3,
                updatedAt = clock.instant(),
            )
            if (store.compareAndSetCommitment(next, current.serverVersion, setOf(RoundCommitmentStatus.COMMITTED, RoundCommitmentStatus.BETTING_ACTIVE))) return
        }
        throw FairnessAuthorityException("COMMIT_VERSION_CONFLICT", "Could not persist accepted client seed for round $roundId")
    }

    private fun evictExpiredCollectors() {
        val cutoff = clock.instant().minus(collectorTtl)
        entropyCollectors.entries.removeIf { it.value.createdAt.isBefore(cutoff) }
    }

    fun deriveAuthoritativeOutcome(tenantId: String, gameId: String, roundId: String): AuthoritativeOutcomeResult {
        ProvablyFairOutcomeBinding.checkBound()
        var durable = store.findCommitment(tenantId, gameId, roundId)
            ?: throw FairnessAuthorityException("COMMITMENT_NOT_FOUND", "Commitment not found for round $roundId")
        AviatorAlgorithmRegistry.requireSupported(durable.algorithmVersion)

        var seeds = resolveClientSeeds(tenantId, gameId, roundId, durable)
        if (durable.clientSeed1 == null || durable.clientSeed2 == null || durable.clientSeed3 == null) {
            var attempt = 0
            while (true) {
                attempt++
                val advanced = durable.copy(
                    clientSeed1 = seeds.first,
                    clientSeed2 = seeds.second,
                    clientSeed3 = seeds.third,
                    updatedAt = clock.instant(),
                )
                if (store.compareAndSetCommitment(advanced, durable.serverVersion, DERIVE_STATUSES)) {
                    durable = advanced
                    break
                }
                val fresh = store.findCommitment(tenantId, gameId, roundId)
                    ?: throw FairnessAuthorityException("COMMITMENT_NOT_FOUND", "Commitment not found for round $roundId")
                durable = fresh
                if (fresh.clientSeed1 != null && fresh.clientSeed2 != null && fresh.clientSeed3 != null) {
                    break
                }
                if (attempt >= MAX_DERIVE_ATTEMPTS) {
                    throw FairnessAuthorityException(
                        "COMMIT_VERSION_CONFLICT",
                        "Commitment ${fresh.commitmentId} client seeds could not be durably accepted"
                    )
                }
                seeds = resolveClientSeeds(tenantId, gameId, roundId, fresh)
            }
        }
        if (durable.clientSeed1 != null && durable.clientSeed2 != null && durable.clientSeed3 != null) {
            seeds = Triple(durable.clientSeed1!!, durable.clientSeed2!!, durable.clientSeed3!!)
        }
        val (cs1, cs2, cs3) = seeds

        val multiplier = AviatorAlgorithmRegistry.compute(
            algorithmVersion = durable.algorithmVersion,
            serverSeed = decryptSeed(durable),
            clientSeed1 = cs1,
            clientSeed2 = cs2,
            clientSeed3 = cs3,
        )

        return AuthoritativeOutcomeResult(
            roundId = roundId,
            commitmentHash = durable.commitmentHash,
            publicSalt = durable.publicSalt,
            multiplier = multiplier,
            algorithmVersion = durable.algorithmVersion,
            rulesVersion = durable.rulesVersion,
            clientSeed1 = cs1,
            clientSeed2 = cs2,
            clientSeed3 = cs3,
        )
    }

    internal fun openCommittedSecret(tenantId: String, gameId: String, roundId: String): String {
        val commitment = store.findCommitment(tenantId, gameId, roundId)
            ?: throw FairnessAuthorityException("COMMITMENT_NOT_FOUND", "Commitment not found for round $roundId")
        return decryptSeed(commitment)
    }

    fun validateCommitmentForReuse(
        commitment: RoundCommitmentRecord,
        expectedRulesVersion: String,
        expectedAlgorithmVersion: String,
        expectedPublicSalt: String,
        expectedAuthorityType: FairnessAuthorityType = FairnessAuthorityType.INTERNAL_HMAC_SHA256,
    ) {
        if (commitment.status != RoundCommitmentStatus.COMMITTED) {
            throw CommitmentStateConflictException(
                "INVALID_STATUS",
                "Commitment ${commitment.commitmentId} status is ${commitment.status}, expected COMMITTED"
            )
        }
        if (commitment.firstBetAcceptedAt != null) {
            throw CommitmentStateConflictException(
                "FIRST_BET_ACCEPTED",
                "Commitment ${commitment.commitmentId} already has first bet accepted at ${commitment.firstBetAcceptedAt}"
            )
        }
        if (commitment.rulesVersion != expectedRulesVersion) {
            throw CommitmentStateConflictException(
                "RULES_VERSION_MISMATCH",
                "Commitment ${commitment.commitmentId} rules version ${commitment.rulesVersion} != expected $expectedRulesVersion"
            )
        }
        if (commitment.algorithmVersion != expectedAlgorithmVersion) {
            throw CommitmentStateConflictException(
                "ALGORITHM_VERSION_MISMATCH",
                "Commitment ${commitment.commitmentId} algorithm version ${commitment.algorithmVersion} != expected $expectedAlgorithmVersion"
            )
        }
        if (commitment.publicSalt != expectedPublicSalt) {
            throw CommitmentStateConflictException(
                "PUBLIC_SALT_MISMATCH",
                "Commitment ${commitment.commitmentId} public salt mismatch"
            )
        }
        if (commitment.authorityType != expectedAuthorityType) {
            throw CommitmentStateConflictException(
                "AUTHORITY_TYPE_MISMATCH",
                "Commitment ${commitment.commitmentId} authority type ${commitment.authorityType} != expected $expectedAuthorityType"
            )
        }
        val plaintextSeed = try {
            decryptSeed(commitment)
        } catch (e: Exception) {
            throw CommitmentStateConflictException(
                "UNDECRYPTABLE_ENVELOPE",
                "Commitment ${commitment.commitmentId} seed envelope cannot be decrypted"
            )
        }
        val calculatedHash = sha256(plaintextSeed)
        if (calculatedHash != commitment.commitmentHash) {
            throw CommitmentStateConflictException(
                "COMMITMENT_HASH_MISMATCH",
                "Commitment ${commitment.commitmentId} decrypted seed hash mismatch"
            )
        }
    }

    private fun decryptSeed(commitment: RoundCommitmentRecord): String {
        val nonce = commitment.secretNonce
            ?: throw FairnessAuthorityException(
                "SECRET_ENVELOPE_MISSING",
                "Commitment ${commitment.commitmentId} has no authenticated seed envelope"
            )
        val sealed = SealedFairnessSeed(
            ciphertextBase64 = commitment.encryptedSecretSeed,
            nonceBase64 = nonce,
            keyId = commitment.secretKeyId ?: FairnessSeedEnvelope.DEFAULT_KEY_ID,
            keyVersion = commitment.secretKeyVersion ?: 1,
            formatVersion = commitment.secretFormatVersion ?: 1,
        )
        return envelope.open(
            tenantId = commitment.tenantId,
            gameId = commitment.gameId,
            roundId = commitment.roundId,
            commitmentId = commitment.commitmentId.toString(),
            sealed = sealed,
        )
    }

    fun revealAndVerifyOutcome(command: RevealOutcomeCommand): RoundRevealRecord {
        ProvablyFairOutcomeBinding.checkBound()
        var attempt = 0
        while (true) {
            attempt++
            try {
                return revealAttempt(command)
            } catch (e: FairnessAuthorityException) {
                if (e.errorCode != "COMMIT_VERSION_CONFLICT" || attempt >= MAX_REVEAL_ATTEMPTS) throw e
            }
        }
    }

    private fun revealAttempt(command: RevealOutcomeCommand): RoundRevealRecord = inTx {
        val now = clock.instant()
        val commitment = store.findCommitment(command.tenantId, command.gameId, command.roundId)
            ?: throw FairnessAuthorityException("COMMITMENT_NOT_FOUND", "Commitment not found for round ${command.roundId}")
        AviatorAlgorithmRegistry.requireSupported(commitment.algorithmVersion)

        val existingReveal = store.findReveal(command.tenantId, command.gameId, command.roundId)
        if (existingReveal != null) {
            if (!store.existsAuditEvent(command.tenantId, commitment.commitmentId, REVEAL_EVENT_KEY)) {
                store.saveAuditEvent(verifiedAudit(command, existingReveal.derivedMultiplier, commitment, now))
            }
            if (commitment.status != RoundCommitmentStatus.REVEALED) {
                val restored = store.compareAndSetCommitment(
                    commitment.copy(status = RoundCommitmentStatus.REVEALED, updatedAt = now),
                    commitment.serverVersion,
                    setOf(
                        RoundCommitmentStatus.COMMITTED,
                        RoundCommitmentStatus.BETTING_ACTIVE,
                        RoundCommitmentStatus.LOCKED,
                        RoundCommitmentStatus.REVEALED,
                    ),
                )
                if (!restored) {
                    val fresh = store.findCommitment(command.tenantId, command.gameId, command.roundId)
                    if (fresh?.status != RoundCommitmentStatus.REVEALED) {
                        throw FairnessAuthorityException(
                            "COMMIT_VERSION_CONFLICT",
                            "Commitment ${commitment.commitmentId} status could not be restored to REVEALED"
                        )
                    }
                }
            }
            entropyCollectors.remove(key(command.tenantId, command.gameId, command.roundId))
            existingReveal
        } else {
            val finalization = outcomeFinalization
            if (finalization != null && commitment.status != RoundCommitmentStatus.REVEALED &&
                !finalization.isFinalizedOutcome(command.tenantId, command.gameId, command.roundId)
            ) {
                throw FairnessAuthorityException(
                    "OUTCOME_NOT_FINALIZED",
                    "Fairness reveal for round ${command.roundId} requires a finalized crash outcome"
                )
            }
            // Verify that revealed secret seed reproduces exact commitment hash
            val plaintextSeed = decryptSeed(commitment)
            val calculatedHash = sha256(plaintextSeed)
            if (calculatedHash != commitment.commitmentHash) {
                store.saveAuditEvent(
                    FairnessAuditRecord(
                        auditId = UUID.randomUUID(),
                        tenantId = command.tenantId,
                        roundId = command.roundId,
                        action = "FAIRNESS_VERIFICATION_FAILED",
                        actor = "SYSTEM_FAIRNESS_AUTHORITY",
                        detail = "Security Alert: Revealed seed $calculatedHash does not match pre-bet commitment ${commitment.commitmentHash} (tampered seed detected)",
                        occurredAt = now,
                        gameId = command.gameId,
                        commitmentId = commitment.commitmentId,
                        eventKey = null,
                    )
                )
                throw FairnessVerificationException(
                    "COMMITMENT_HASH_MISMATCH",
                    "Revealed secret seed does not match published pre-bet commitment hash"
                )
            }

            val (cs1, cs2, cs3) = resolveClientSeeds(command.tenantId, command.gameId, command.roundId, commitment)
            val fallbackMode = listOf(cs1, cs2, cs3).zip(1..3).any { (seed, slot) ->
                seed == sha256("${commitment.commitmentHash}:fallback:$slot:${command.roundId}")
            }

            // Derive authoritative multiplier
            val derivedMultiplier = AviatorAlgorithmRegistry.compute(
                algorithmVersion = commitment.algorithmVersion,
                serverSeed = plaintextSeed,
                clientSeed1 = cs1,
                clientSeed2 = cs2,
                clientSeed3 = cs3,
            )

            val advanced = commitment.copy(
                status = RoundCommitmentStatus.REVEALED,
                updatedAt = now,
                clientSeed1 = cs1,
                clientSeed2 = cs2,
                clientSeed3 = cs3,
            )
            val applied = store.compareAndSetCommitment(
                advanced,
                commitment.serverVersion,
                setOf(
                    RoundCommitmentStatus.COMMITTED,
                    RoundCommitmentStatus.BETTING_ACTIVE,
                    RoundCommitmentStatus.LOCKED,
                    RoundCommitmentStatus.REVEALED,
                ),
            )
            if (!applied) {
                throw FairnessAuthorityException(
                    "COMMIT_VERSION_CONFLICT",
                    "Commitment ${commitment.commitmentId} changed during reveal; re-reading for idempotent retry"
                )
            }

            val evidenceRef = sha256("${command.tenantId}:${command.roundId}:$plaintextSeed:$derivedMultiplier:${now.toEpochMilli()}")

            val reveal = RoundRevealRecord(
                revealId = UUID.randomUUID(),
                commitmentId = commitment.commitmentId,
                tenantId = command.tenantId,
                gameId = command.gameId,
                roundId = command.roundId,
                revealedSecretSeed = plaintextSeed,
                derivedMultiplier = derivedMultiplier,
                revealedAt = now,
                verificationStatus = FairnessVerificationStatus.VERIFIED,
                verificationError = null,
                evidenceReference = evidenceRef,
                fallbackMode = fallbackMode,
            )

            store.saveReveal(reveal)
            entropyCollectors.remove(key(command.tenantId, command.gameId, command.roundId))
            if (!store.existsAuditEvent(command.tenantId, commitment.commitmentId, REVEAL_EVENT_KEY)) {
                store.saveAuditEvent(verifiedAudit(command, derivedMultiplier, commitment, now))
            }
            reveal
        }
    }

    private fun verifiedAudit(
        command: RevealOutcomeCommand,
        derivedMultiplier: BigDecimal,
        commitment: RoundCommitmentRecord,
        occurredAt: Instant,
    ): FairnessAuditRecord = FairnessAuditRecord(
        auditId = UUID.randomUUID(),
        tenantId = command.tenantId,
        roundId = command.roundId,
        action = REVEAL_EVENT_KEY,
        actor = "SYSTEM_FAIRNESS_AUTHORITY",
        detail = "Verified outcome multiplier $derivedMultiplier against pre-bet commitment ${commitment.commitmentHash}",
        occurredAt = occurredAt,
        gameId = command.gameId,
        commitmentId = commitment.commitmentId,
        eventKey = REVEAL_EVENT_KEY,
    )

    fun executeProviderFairnessReconciliation(
        tenantId: String,
        gameId: String,
        roundId: String,
        providerPort: ExternalFairnessProviderPort
    ): FairnessReconciliationResult {
        ProvablyFairOutcomeBinding.checkBound()
        val now = clock.instant()
        val commitment = store.findCommitment(tenantId, gameId, roundId)
            ?: throw FairnessAuthorityException("COMMITMENT_NOT_FOUND", "Commitment not found for round $roundId")

        return try {
            val externalOutcome = providerPort.fetchOutcome(tenantId, gameId, roundId)
            FairnessReconciliationResult(
                roundId = roundId,
                status = FairnessReconciliationStatus.RESOLVED_ACCEPTED,
                safeMessage = "Provider outcome resolved with multiplier ${externalOutcome.multiplier}",
            )
        } catch (e: ExternalFairnessProviderTimeoutException) {
            commitment.status = RoundCommitmentStatus.LOCKED
            commitment.updatedAt = now
            store.updateCommitment(commitment)

            store.saveAuditEvent(
                FairnessAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = tenantId,
                    roundId = roundId,
                    action = "EXTERNAL_PROVIDER_TIMEOUT",
                    actor = "SYSTEM_FAIRNESS_AUTHORITY",
                    detail = "Fairness reconciliation held: provider timed out (${e.message})",
                    occurredAt = now,
                )
            )

            FairnessReconciliationResult(
                roundId = roundId,
                status = FairnessReconciliationStatus.HELD_PENDING_RECONCILIATION,
                safeMessage = e.message,
            )
        }
    }

    companion object {
        const val MAX_REVEAL_ATTEMPTS = 3
        const val MAX_DERIVE_ATTEMPTS = 3
        const val REVEAL_EVENT_KEY = "ROUND_OUTCOME_REVEALED_AND_VERIFIED"

        val DERIVE_STATUSES = setOf(
            RoundCommitmentStatus.COMMITTED,
            RoundCommitmentStatus.BETTING_ACTIVE,
            RoundCommitmentStatus.LOCKED,
            RoundCommitmentStatus.REVEALED,
        )

        fun sha256(input: String): String {
            val md = MessageDigest.getInstance("SHA-256")
            val bytes = md.digest(input.toByteArray(StandardCharsets.UTF_8))
            return bytes.joinToString("") { "%02x".format(it) }
        }

        fun sha512(input: String): String {
            val md = MessageDigest.getInstance("SHA-512")
            val bytes = md.digest(input.toByteArray(StandardCharsets.UTF_8))
            return bytes.joinToString("") { "%02x".format(it) }
        }

        fun computeMultiplier(
            serverSeed: String,
            clientSeed1: String,
            clientSeed2: String,
            clientSeed3: String,
        ): BigDecimal = AviatorAlgorithmRegistry.compute(
            algorithmVersion = AviatorAlgorithmRegistry.VERSION_1_0_0,
            serverSeed = serverSeed,
            clientSeed1 = clientSeed1,
            clientSeed2 = clientSeed2,
            clientSeed3 = clientSeed3,
        )
    }
}
