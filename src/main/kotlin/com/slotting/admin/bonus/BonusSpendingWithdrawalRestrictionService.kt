package com.slotting.admin.bonus

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to enforce BONUS-001-02: Enforce bonus spending and withdrawal restrictions.
 * Semantic contract: "Cash/bonus conservation and isolation; conversion prohibited unless explicitly approved."
 * Protected risk: "bonus spent/withdrawn as cash"
 */
object BonusSpendingWithdrawalRestrictionBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("bonus spent/withdrawn as cash")
        }
    }
}

data class GameWageringRule(
    val gameId: String,
    val isBonusAllowed: Boolean,
    val contributionMultiplier: Double = 1.0, // 1.0 = 100%, 0.5 = 50%, 0.0 = 0%
    val maxAllowedBetMinorUnits: Long = 500L // e.g. $5.00 max bet with active bonus
)

data class ExecuteWagerCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val playerId: UUID,
    val gameId: String,
    val wagerMinorUnits: Long,
    val currencyCode: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long
)

data class ExecuteWagerResult(
    val resultId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val gameId: String,
    val cashDebitedMinorUnits: Long,
    val bonusDebitedMinorUnits: Long,
    val remainingCashMinorUnits: Long,
    val remainingBonusMinorUnits: Long,
    val wageringProgressAddedMinorUnits: Long,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class SettleWinningsCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val playerId: UUID,
    val gameId: String,
    val roundId: String,
    val payoutMinorUnits: Long,
    val bonusFundingRatio: Double, // 0.0 to 1.0 proportion funded by bonus
    val currencyCode: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long
)

data class SettleWinningsResult(
    val resultId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val roundId: String,
    val cashCreditedMinorUnits: Long,
    val bonusCreditedMinorUnits: Long,
    val newCashMinorUnits: Long,
    val newBonusMinorUnits: Long,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class ExecuteRestrictedWithdrawalCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val playerId: UUID,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val forfeitActiveBonusOnWithdrawal: Boolean = false,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long
)

data class RestrictedWithdrawalResult(
    val resultId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val withdrawnCashMinorUnits: Long,
    val forfeitedBonusMinorUnits: Long,
    val remainingCashMinorUnits: Long,
    val remainingBonusMinorUnits: Long,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

interface GameRuleDirectory {
    fun findRule(tenantId: String, gameId: String): GameWageringRule?
}

class InMemoryGameRuleDirectory : GameRuleDirectory {
    val rules = ConcurrentHashMap<String, GameWageringRule>()

    fun setRule(tenantId: String, rule: GameWageringRule) {
        rules["$tenantId:${rule.gameId}"] = rule
    }

    override fun findRule(tenantId: String, gameId: String): GameWageringRule? {
        return rules["$tenantId:$gameId"]
    }
}

class BonusSpendingWithdrawalRestrictionService(
    private val store: BonusGrantStore,
    private val gameRules: GameRuleDirectory,
    private val alertSink: BonusAlertSink = InMemoryBonusAlertSink(),
    private val clock: Clock = Clock.systemUTC()
) {

    private fun validateHeaders(
        tenantId: String,
        correlationId: String,
        causationId: String,
        idempotencyKey: String,
        expectedVersion: Long
    ) {
        if (tenantId.isBlank() || correlationId.isBlank() || causationId.isBlank() || idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (expectedVersion <= 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
    }

    private fun computeFingerprint(command: ExecuteWagerCommand): String {
        return listOf(
            command.principal?.tenantId,
            command.principal?.id,
            command.tenantId,
            command.playerId.toString(),
            command.gameId,
            command.wagerMinorUnits,
            command.currencyCode,
            command.expectedVersion
        ).joinToString("|")
    }

    private fun computeFingerprint(command: SettleWinningsCommand): String {
        return listOf(
            command.principal?.tenantId,
            command.principal?.id,
            command.tenantId,
            command.playerId.toString(),
            command.gameId,
            command.roundId,
            command.payoutMinorUnits,
            command.bonusFundingRatio,
            command.currencyCode,
            command.expectedVersion
        ).joinToString("|")
    }

    private fun computeFingerprint(command: ExecuteRestrictedWithdrawalCommand): String {
        return listOf(
            command.principal?.tenantId,
            command.principal?.id,
            command.tenantId,
            command.playerId.toString(),
            command.amountMinorUnits,
            command.currencyCode,
            command.forfeitActiveBonusOnWithdrawal,
            command.expectedVersion
        ).joinToString("|")
    }

    fun executeWager(command: ExecuteWagerCommand): ExecuteWagerResult = synchronized(store) {
        // 1. Fail-closed binding check
        BonusSpendingWithdrawalRestrictionBinding.checkBound()

        // 2. Header and parameter validations
        validateHeaders(
            tenantId = command.tenantId,
            correlationId = command.correlationId,
            causationId = command.causationId,
            idempotencyKey = command.idempotencyKey,
            expectedVersion = command.expectedVersion
        )

        if (command.wagerMinorUnits <= 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 3. Idempotency check
        val fingerprint = computeFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint && cachedRes is ExecuteWagerResult) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        // 4. Principal check
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (principal.kind == PrincipalKind.PLAYER && principal.id != command.playerId.toString()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val wallet = store.findWallet(command.tenantId, command.playerId, command.currencyCode)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (command.expectedVersion != wallet.version) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        if (command.wagerMinorUnits > wallet.totalBalanceMinorUnits) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val gameRule = gameRules.findRule(command.tenantId, command.gameId)
            ?: GameWageringRule(gameId = command.gameId, isBonusAllowed = true)

        // 5. Calculate spending order: Cash first, then Bonus
        val cashAvailable = wallet.cashMinorUnits
        val cashDebit = minOf(command.wagerMinorUnits, cashAvailable)
        val bonusDebit = command.wagerMinorUnits - cashDebit

        // 6. Bonus spending restrictions check
        if (bonusDebit > 0L) {
            // Rule A: Excluded games cannot use bonus funds
            if (!gameRule.isBonusAllowed) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    alertType = "BONUS_SPENDING_ON_EXCLUDED_GAME_DENIED",
                    message = "Player ${command.playerId} attempted bonus wager on excluded game ${command.gameId}"
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }

            // Rule B: Max allowed bet cap with active bonus
            if (command.wagerMinorUnits > gameRule.maxAllowedBetMinorUnits) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    alertType = "BONUS_MAX_BET_EXCEEDED",
                    message = "Wager of ${command.wagerMinorUnits} exceeds max allowed bonus bet of ${gameRule.maxAllowedBetMinorUnits}"
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        val now = clock.instant()
        wallet.cashMinorUnits -= cashDebit
        wallet.bonusMinorUnits -= bonusDebit
        wallet.version += 1L
        store.saveWallet(wallet)

        // 7. Double-entry ledger recording: conservation
        if (cashDebit > 0L) {
            store.recordLedgerEntry(
                BonusLedgerEntry(
                    entryId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    transactionReference = "wager-cash:${UUID.randomUUID()}",
                    debitAccount = "PLAYER_CASH_LIABILITY:${wallet.playerId}",
                    creditAccount = "GAME_WAGER_ESCROW:${command.gameId}",
                    amountMinorUnits = cashDebit,
                    currencyCode = command.currencyCode,
                    createdAt = now
                )
            )
        }
        if (bonusDebit > 0L) {
            store.recordLedgerEntry(
                BonusLedgerEntry(
                    entryId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    transactionReference = "wager-bonus:${UUID.randomUUID()}",
                    debitAccount = "PLAYER_BONUS_LIABILITY:${wallet.playerId}",
                    creditAccount = "BONUS_WAGER_ESCROW:${command.gameId}",
                    amountMinorUnits = bonusDebit,
                    currencyCode = command.currencyCode,
                    createdAt = now
                )
            )
        }

        // 8. Progress wagering requirements on active grants
        val wageringAdded = (bonusDebit * gameRule.contributionMultiplier).toLong()

        val resultId = UUID.randomUUID()
        val evidenceReference = "bonus-wager:${command.tenantId}:${command.playerId}:${command.gameId}:$resultId:${wallet.version}"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "WAGER_EXECUTED_WITH_RESTRICTIONS",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "WAGER_EXECUTED_WITH_RESTRICTIONS",
            createdAt = now
        )

        val result = ExecuteWagerResult(
            resultId = resultId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            gameId = command.gameId,
            cashDebitedMinorUnits = cashDebit,
            bonusDebitedMinorUnits = bonusDebit,
            remainingCashMinorUnits = wallet.cashMinorUnits,
            remainingBonusMinorUnits = wallet.bonusMinorUnits,
            wageringProgressAddedMinorUnits = wageringAdded,
            serverTime = now,
            serverVersion = wallet.version,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    fun settleWinnings(command: SettleWinningsCommand): SettleWinningsResult = synchronized(store) {
        BonusSpendingWithdrawalRestrictionBinding.checkBound()

        validateHeaders(
            tenantId = command.tenantId,
            correlationId = command.correlationId,
            causationId = command.causationId,
            idempotencyKey = command.idempotencyKey,
            expectedVersion = command.expectedVersion
        )

        val fingerprint = computeFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint && cachedRes is SettleWinningsResult) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val wallet = store.findWallet(command.tenantId, command.playerId, command.currencyCode)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (command.expectedVersion != wallet.version) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        if (command.payoutMinorUnits <= 0L || command.bonusFundingRatio < 0.0 || command.bonusFundingRatio > 1.0) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Payout split: bonus ratio of winnings must route back to BONUS bucket
        val bonusRatio = command.bonusFundingRatio
        val bonusCredited = (command.payoutMinorUnits * bonusRatio).toLong()
        val cashCredited = command.payoutMinorUnits - bonusCredited

        val now = clock.instant()
        wallet.cashMinorUnits += cashCredited
        wallet.bonusMinorUnits += bonusCredited
        wallet.version += 1L
        store.saveWallet(wallet)

        // Double entry ledger for winnings
        if (cashCredited > 0L) {
            store.recordLedgerEntry(
                BonusLedgerEntry(
                    entryId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    transactionReference = "win-cash:${command.roundId}",
                    debitAccount = "GAME_WAGER_ESCROW:${command.gameId}",
                    creditAccount = "PLAYER_CASH_LIABILITY:${wallet.playerId}",
                    amountMinorUnits = cashCredited,
                    currencyCode = command.currencyCode,
                    createdAt = now
                )
            )
        }
        if (bonusCredited > 0L) {
            store.recordLedgerEntry(
                BonusLedgerEntry(
                    entryId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    transactionReference = "win-bonus:${command.roundId}",
                    debitAccount = "BONUS_WAGER_ESCROW:${command.gameId}",
                    creditAccount = "PLAYER_BONUS_LIABILITY:${wallet.playerId}",
                    amountMinorUnits = bonusCredited,
                    currencyCode = command.currencyCode,
                    createdAt = now
                )
            )
        }

        val resultId = UUID.randomUUID()
        val evidenceReference = "winnings-settle:${command.tenantId}:${command.playerId}:${command.roundId}:$resultId:${wallet.version}"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "WINNINGS_SETTLED_WITH_RESTRICTIONS",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "WINNINGS_SETTLED_WITH_RESTRICTIONS",
            createdAt = now
        )

        val result = SettleWinningsResult(
            resultId = resultId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            roundId = command.roundId,
            cashCreditedMinorUnits = cashCredited,
            bonusCreditedMinorUnits = bonusCredited,
            newCashMinorUnits = wallet.cashMinorUnits,
            newBonusMinorUnits = wallet.bonusMinorUnits,
            serverTime = now,
            serverVersion = wallet.version,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    fun executeRestrictedWithdrawal(command: ExecuteRestrictedWithdrawalCommand): RestrictedWithdrawalResult = synchronized(store) {
        BonusSpendingWithdrawalRestrictionBinding.checkBound()

        validateHeaders(
            tenantId = command.tenantId,
            correlationId = command.correlationId,
            causationId = command.causationId,
            idempotencyKey = command.idempotencyKey,
            expectedVersion = command.expectedVersion
        )

        if (command.amountMinorUnits <= 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = computeFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint && cachedRes is RestrictedWithdrawalResult) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (principal.kind == PrincipalKind.PLAYER && principal.id != command.playerId.toString()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val wallet = store.findWallet(command.tenantId, command.playerId, command.currencyCode)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (command.expectedVersion != wallet.version) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // CORE ENFORCEMENT 1: Withdrawing more than cash balance is strictly FORBIDDEN!
        if (command.amountMinorUnits > wallet.cashMinorUnits) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                alertType = "BONUS_WITHDRAWAL_DENIED",
                message = "Player ${command.playerId} attempted to withdraw ${command.amountMinorUnits} exceeding cash balance ${wallet.cashMinorUnits}"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // CORE ENFORCEMENT 2: If active bonus exists, withdrawal requires explicit forfeiture confirmation
        var forfeitedBonus = 0L
        if (wallet.bonusMinorUnits > 0L) {
            if (!command.forfeitActiveBonusOnWithdrawal) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    alertType = "ACTIVE_BONUS_FORFEITURE_REQUIRED",
                    message = "Player ${command.playerId} has active bonus ${wallet.bonusMinorUnits} without forfeiture consent"
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            } else {
                forfeitedBonus = wallet.bonusMinorUnits
                wallet.bonusMinorUnits = 0L
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    alertType = "BONUS_FORFEITED_ON_WITHDRAWAL",
                    message = "Player ${command.playerId} forfeited $forfeitedBonus bonus on cash withdrawal"
                )
            }
        }

        val now = clock.instant()
        wallet.cashMinorUnits -= command.amountMinorUnits
        wallet.version += 1L
        store.saveWallet(wallet)

        // Ledger: Cash withdrawal debit
        store.recordLedgerEntry(
            BonusLedgerEntry(
                entryId = UUID.randomUUID(),
                tenantId = command.tenantId,
                transactionReference = "restricted-withdrawal:${UUID.randomUUID()}",
                debitAccount = "PLAYER_CASH_LIABILITY:${wallet.playerId}",
                creditAccount = "PAYMENT_SETTLEMENT_OUTBOX",
                amountMinorUnits = command.amountMinorUnits,
                currencyCode = command.currencyCode,
                createdAt = now
            )
        )

        // Ledger: Forfeited bonus recovery
        if (forfeitedBonus > 0L) {
            store.recordLedgerEntry(
                BonusLedgerEntry(
                    entryId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    transactionReference = "bonus-forfeit:${UUID.randomUUID()}",
                    debitAccount = "PLAYER_BONUS_LIABILITY:${wallet.playerId}",
                    creditAccount = "CASINO_BONUS_FORFEITURE_RECOVERY",
                    amountMinorUnits = forfeitedBonus,
                    currencyCode = command.currencyCode,
                    createdAt = now
                )
            )
        }

        val resultId = UUID.randomUUID()
        val evidenceReference = "restricted-withdrawal:${command.tenantId}:${command.playerId}:$resultId:${wallet.version}"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "RESTRICTED_WITHDRAWAL_COMPLETED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "RESTRICTED_WITHDRAWAL_COMPLETED",
            createdAt = now
        )

        val result = RestrictedWithdrawalResult(
            resultId = resultId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            withdrawnCashMinorUnits = command.amountMinorUnits,
            forfeitedBonusMinorUnits = forfeitedBonus,
            remainingCashMinorUnits = wallet.cashMinorUnits,
            remainingBonusMinorUnits = wallet.bonusMinorUnits,
            serverTime = now,
            serverVersion = wallet.version,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }
}
