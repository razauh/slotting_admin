package com.slotting.admin.payment

import com.slotting.admin.auth.*
import com.slotting.admin.ledger.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Fail-closed verification gate for PAYMENT-005: Server-only deposit credit.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Server-only deposit credit.
 * Rationale: It exists to prevent: app return/client request credits.
 */
object ServerOnlyDepositCreditBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("app return/client request credits")
        }
    }
}

/**
 * Outcome-specific semantic contract for PAYMENT-005.
 */
const val SERVER_ONLY_DEPOSIT_CREDIT_CONTRACT =
    "Exactly one credit per provider transaction; callback failure retries safely."

enum class CreditSource {
    CLIENT_REQUEST,
    APP_RETURN_URL,
    SERVER_VERIFIED_WEBHOOK,
}

data class CreditDepositCommand(
    val tenantId: String,
    val playerId: UUID,
    val paymentReference: String,
    val providerId: String,
    val providerTransactionId: String,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val source: CreditSource,
    val returnUrlParameters: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val principal: AuthenticatedPrincipal? = null,
)

data class CreditDepositResult(
    val resultId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val paymentReference: String,
    val providerTransactionId: String,
    val creditedAmountMinorUnits: Long,
    val currencyCode: String,
    val ledgerTransactionReference: String,
    val isDuplicate: Boolean,
    val conserved: Boolean,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val evidenceReference: String,
    val serverTime: Instant,
    val semanticContract: String = SERVER_ONLY_DEPOSIT_CREDIT_CONTRACT,
)

data class ServerDepositCreditRecord(
    val creditId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val paymentReference: String,
    val providerTransactionId: String,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val ledgerTransactionReference: String,
    val source: CreditSource,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val conserved: Boolean,
    val evidenceReference: String,
    val idempotencyKey: String,
    val createdAt: Instant,
    val version: Long,
    val semanticContract: String = SERVER_ONLY_DEPOSIT_CREDIT_CONTRACT,
)

data class ServerDepositCreditSnapshot(
    val credits: Map<String, ServerDepositCreditRecord>,
    val creditsByTxId: Map<String, ServerDepositCreditRecord>,
    val idempotencyMap: Map<String, Pair<String, CreditDepositResult>>,
    val auditEvents: List<AuditEvent>,
    val outboxEvents: List<OutboxEvent>,
)

interface ServerDepositCreditAlertSink {
    fun sendAlert(tenantId: String, paymentReference: String, alertType: String, reason: String, detail: String)
}

class InMemoryServerDepositCreditAlertSink : ServerDepositCreditAlertSink {
    val alerts = mutableListOf<String>()

    @Synchronized
    override fun sendAlert(tenantId: String, paymentReference: String, alertType: String, reason: String, detail: String) {
        alerts.add("$tenantId:$paymentReference:$alertType:$reason:$detail")
    }
}

interface ServerDepositCreditStore {
    fun findCreditByPaymentRef(tenantId: String, paymentReference: String): ServerDepositCreditRecord?
    fun findCreditByProviderTxId(tenantId: String, providerTransactionId: String): ServerDepositCreditRecord?
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CreditDepositResult>?
    fun saveCredit(
        record: ServerDepositCreditRecord,
        result: CreditDepositResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun getAuditEvents(): List<AuditEvent>
    fun getOutboxEvents(): List<OutboxEvent>
    fun exportSnapshot(): ServerDepositCreditSnapshot
    fun importSnapshot(snapshot: ServerDepositCreditSnapshot)
}

class InMemoryServerDepositCreditStore : ServerDepositCreditStore {
    private val credits = ConcurrentHashMap<String, ServerDepositCreditRecord>()
    private val creditsByTxId = ConcurrentHashMap<String, ServerDepositCreditRecord>()
    private val idempotencyResults = ConcurrentHashMap<String, Pair<String, CreditDepositResult>>()
    private val auditEvents = mutableListOf<AuditEvent>()
    private val outboxEvents = mutableListOf<OutboxEvent>()

    private fun pKey(tenantId: String, ref: String) = "$tenantId:$ref"
    private fun txKey(tenantId: String, txId: String) = "$tenantId:$txId"
    private fun idKey(tenantId: String, idemp: String) = "$tenantId:$idemp"

    @Synchronized
    override fun findCreditByPaymentRef(tenantId: String, paymentReference: String): ServerDepositCreditRecord? =
        credits[pKey(tenantId, paymentReference)]?.copy()

    @Synchronized
    override fun findCreditByProviderTxId(tenantId: String, providerTransactionId: String): ServerDepositCreditRecord? =
        creditsByTxId[txKey(tenantId, providerTransactionId)]?.copy()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CreditDepositResult>? =
        idempotencyResults[idKey(tenantId, idempotencyKey)]

    @Synchronized
    override fun saveCredit(
        record: ServerDepositCreditRecord,
        result: CreditDepositResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        credits[pKey(record.tenantId, record.paymentReference)] = record.copy()
        creditsByTxId[txKey(record.tenantId, record.providerTransactionId)] = record.copy()
        idempotencyResults[idKey(record.tenantId, idempotencyKey)] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun getAuditEvents(): List<AuditEvent> = auditEvents.toList()

    @Synchronized
    override fun getOutboxEvents(): List<OutboxEvent> = outboxEvents.toList()

    @Synchronized
    override fun exportSnapshot(): ServerDepositCreditSnapshot = ServerDepositCreditSnapshot(
        credits = HashMap(credits),
        creditsByTxId = HashMap(creditsByTxId),
        idempotencyMap = HashMap(idempotencyResults),
        auditEvents = ArrayList(auditEvents),
        outboxEvents = ArrayList(outboxEvents),
    )

    @Synchronized
    override fun importSnapshot(snapshot: ServerDepositCreditSnapshot) {
        credits.clear()
        credits.putAll(snapshot.credits)
        creditsByTxId.clear()
        creditsByTxId.putAll(snapshot.creditsByTxId)
        idempotencyResults.clear()
        idempotencyResults.putAll(snapshot.idempotencyMap)
        auditEvents.clear()
        auditEvents.addAll(snapshot.auditEvents)
        outboxEvents.clear()
        outboxEvents.addAll(snapshot.outboxEvents)
    }
}

class ServerOnlyDepositCreditService(
    private val ledgerPostingService: LedgerPostingService,
    private val store: ServerDepositCreditStore,
    private val alertSink: ServerDepositCreditAlertSink = InMemoryServerDepositCreditAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprint(cmd: CreditDepositCommand): String {
        return sha256("${cmd.tenantId}:${cmd.playerId}:${cmd.paymentReference}:${cmd.providerId}:${cmd.providerTransactionId}:${cmd.amountMinorUnits}:${cmd.currencyCode}:${cmd.source}:${cmd.expectedVersion}")
    }

    @Synchronized
    fun creditDeposit(command: CreditDepositCommand): CreditDepositResult {
        // Protected risk assertion: app return/client request credits
        ServerOnlyDepositCreditBinding.checkBound()

        // 1. App return / client request credits MUST BE REJECTED!
        // Rationale: "It exists to prevent: app return/client request credits."
        // Semantic contract: "return URL is informational only", untrusted client request cannot credit balance.
        if (command.source == CreditSource.CLIENT_REQUEST || command.source == CreditSource.APP_RETURN_URL) {
            alertSink.sendAlert(
                tenantId = command.tenantId.ifBlank { "UNKNOWN" },
                paymentReference = command.paymentReference.ifBlank { "UNKNOWN" },
                alertType = "CLIENT_CREDIT_ATTEMPT_DENIED",
                reason = "APP_RETURN_OR_CLIENT_REQUEST_FORBIDDEN",
                detail = "Rejected non-authoritative client credit request from source: ${command.source}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 2. Mandatory Input Validation
        if (command.tenantId.isBlank() ||
            command.paymentReference.isBlank() ||
            command.providerId.isBlank() ||
            command.providerTransactionId.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            alertSink.sendAlert(
                tenantId = command.tenantId.ifBlank { "UNKNOWN" },
                paymentReference = command.paymentReference.ifBlank { "UNKNOWN" },
                alertType = "DEPOSIT_CREDIT_INVALID_INPUT",
                reason = "BLANK_MANDATORY_FIELDS",
                detail = "Credit deposit command rejected due to blank mandatory fields",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.amountMinorUnits <= 0L || !command.currencyCode.matches(Regex("^[A-Z]{3}$"))) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 3. Principal Authorization Check: Server-only source requires authoritative caller
        command.principal?.let { principal ->
            if (principal.tenantId != command.tenantId) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            if (principal.kind != PrincipalKind.ADMIN) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            if (principal.roles.none { it in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY) }) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        val fp = fingerprint(command)
        val now = clock.instant()

        // 4. Idempotency Check: By Idempotency Key
        val existingIdemp = store.findByIdempotency(command.tenantId, command.idempotencyKey)
        if (existingIdemp != null) {
            val (cachedFp, cachedResult) = existingIdemp
            if (cachedFp != fp) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    paymentReference = command.paymentReference,
                    alertType = "DEPOSIT_CREDIT_IDEMPOTENCY_CONFLICT",
                    reason = "PAYLOAD_MISMATCH",
                    detail = "Payload conflict detected under idempotency key ${command.idempotencyKey}",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return cachedResult.copy(isDuplicate = true)
        }

        // 5. Exactly one credit per provider transaction
        // Check if providerTransactionId already credited
        val existingByTxId = store.findCreditByProviderTxId(command.tenantId, command.providerTransactionId)
        if (existingByTxId != null) {
            if (existingByTxId.paymentReference != command.paymentReference ||
                existingByTxId.amountMinorUnits != command.amountMinorUnits ||
                existingByTxId.currencyCode != command.currencyCode
            ) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    paymentReference = command.paymentReference,
                    alertType = "PROVIDER_TRANSACTION_CONFLICT",
                    reason = "DUPLICATE_PROVIDER_TX_DIFFERENT_PAYLOAD",
                    detail = "Provider transaction ID ${command.providerTransactionId} already used with different payload",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }

            // Exactly identical replay under different idempotency key -> return duplicate result
            val resultId = UUID.randomUUID()
            return CreditDepositResult(
                resultId = resultId,
                tenantId = command.tenantId,
                playerId = command.playerId,
                paymentReference = command.paymentReference,
                providerTransactionId = command.providerTransactionId,
                creditedAmountMinorUnits = existingByTxId.amountMinorUnits,
                currencyCode = existingByTxId.currencyCode,
                ledgerTransactionReference = existingByTxId.ledgerTransactionReference,
                isDuplicate = true,
                conserved = existingByTxId.conserved,
                debitMinorUnits = existingByTxId.debitMinorUnits,
                creditMinorUnits = existingByTxId.creditMinorUnits,
                evidenceReference = existingByTxId.evidenceReference,
                serverTime = now,
                semanticContract = SERVER_ONLY_DEPOSIT_CREDIT_CONTRACT,
            )
        }

        // Check if payment reference already credited
        val existingByPaymentRef = store.findCreditByPaymentRef(command.tenantId, command.paymentReference)
        if (existingByPaymentRef != null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 6. Post to Double-Entry Ledger via LEDGER-002 Posting Service
        // "Exactly one credit per provider transaction; callback failure retries safely."
        val ledgerTxRef = "TX-DEP-${command.paymentReference}"
        val adminPrincipal = command.principal ?: AuthenticatedPrincipal(
            id = "sys-payment-worker",
            tenantId = command.tenantId,
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPER_ADMIN),
        )

        val postCommand = PostTransactionCommand(
            principal = adminPrincipal,
            tenantId = command.tenantId,
            transactionReference = ledgerTxRef,
            currencyCode = command.currencyCode,
            entries = listOf(
                JournalEntryDraft(
                    accountReference = "gateway:clearing:${command.providerId}",
                    direction = JournalEntryDirection.DEBIT,
                    amountMinorUnits = command.amountMinorUnits,
                    currencyCode = command.currencyCode,
                    narration = "Gateway clearing debit for deposit ${command.paymentReference}",
                ),
                JournalEntryDraft(
                    accountReference = "player:wallet:${command.playerId}",
                    direction = JournalEntryDirection.CREDIT,
                    amountMinorUnits = command.amountMinorUnits,
                    currencyCode = command.currencyCode,
                    narration = "Player wallet credit for deposit ${command.paymentReference}",
                ),
            ),
            idempotencyKey = "ledger-post-${command.idempotencyKey}",
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val postingResult = try {
            ledgerPostingService.postTransaction(postCommand)
        } catch (e: Exception) {
            // Callback failure retries safely: do not commit local credit if ledger posting fails
            alertSink.sendAlert(
                tenantId = command.tenantId,
                paymentReference = command.paymentReference,
                alertType = "DEPOSIT_CREDIT_LEDGER_POSTING_FAILED",
                reason = "LEDGER_FAILURE",
                detail = "Failed to post deposit credit to ledger: ${e.message}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        val creditId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = "DEP-CRED-EVID-$creditId"

        val record = ServerDepositCreditRecord(
            creditId = creditId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            paymentReference = command.paymentReference,
            providerTransactionId = command.providerTransactionId,
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            ledgerTransactionReference = ledgerTxRef,
            source = command.source,
            debitMinorUnits = postingResult.totalDebitsMinorUnits,
            creditMinorUnits = postingResult.totalCreditsMinorUnits,
            conserved = postingResult.isBalanced,
            evidenceReference = evidenceRef,
            idempotencyKey = command.idempotencyKey,
            createdAt = now,
            version = 1L,
            semanticContract = SERVER_ONLY_DEPOSIT_CREDIT_CONTRACT,
        )

        val result = CreditDepositResult(
            resultId = resultId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            paymentReference = command.paymentReference,
            providerTransactionId = command.providerTransactionId,
            creditedAmountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            ledgerTransactionReference = ledgerTxRef,
            isDuplicate = false,
            conserved = postingResult.isBalanced,
            debitMinorUnits = postingResult.totalDebitsMinorUnits,
            creditMinorUnits = postingResult.totalCreditsMinorUnits,
            evidenceReference = evidenceRef,
            serverTime = now,
            semanticContract = SERVER_ONLY_DEPOSIT_CREDIT_CONTRACT,
        )

        val audit = AuditEvent(UUID.randomUUID(), creditId, command.tenantId, "SERVER_DEPOSIT_CREDITED", now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), creditId, command.tenantId, "SERVER_DEPOSIT_CREDITED", now)
        store.saveCredit(record, result, command.idempotencyKey, fp, audit, outbox)

        return result
    }
}
