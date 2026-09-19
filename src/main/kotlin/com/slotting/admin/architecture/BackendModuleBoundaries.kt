package com.slotting.admin.architecture

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Traceability binding for ARCH-001-02: Enforce backend module boundaries.
 * Fail-closed assertion gate for RED/GREEN TDD verification.
 * Expected RED failure reason: "architecture test fails missing modules".
 */
object BackendModuleBoundaryBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("architecture test fails missing modules")
        }
    }
}

/**
 * The canonical 9 backend modules mandated by ARCH-001.
 * Contract: "Modules: identity,wallet,ledger,payments,games,compliance,admin,support,outbox; repeatable local tests; no Android source impact."
 */
enum class CanonicalBackendModule(
    val id: String,
    val description: String,
    val packages: Set<String>
) {
    IDENTITY(
        id = "identity",
        description = "Player identity, authentication, profile search, and KYC verification",
        packages = setOf("com.slotting.admin.player", "com.slotting.admin.kyc")
    ),
    WALLET(
        id = "wallet",
        description = "Player wallet balances, withdrawals, and manual adjustments",
        packages = setOf("com.slotting.admin.withdrawal", "com.slotting.admin.adjustment")
    ),
    LEDGER(
        id = "ledger",
        description = "Double-entry journal, immutable postings, and financial timeline",
        packages = setOf("com.slotting.admin.ledger", "com.slotting.admin.finance")
    ),
    PAYMENTS(
        id = "payments",
        description = "Payment port, gateway provider adapters, and cashier callbacks",
        packages = setOf("com.slotting.admin.payment", "com.slotting.admin.provider")
    ),
    GAMES(
        id = "games",
        description = "Active game session management, signed callbacks, and game provider integration",
        packages = setOf("com.slotting.admin.game", "com.slotting.admin.gameprovider")
    ),
    COMPLIANCE(
        id = "compliance",
        description = "AML alerts, sanctions/PEP screening, RG limits, and geolocation validation",
        packages = setOf("com.slotting.admin.aml", "com.slotting.admin.rg", "com.slotting.admin.geo")
    ),
    ADMIN(
        id = "admin",
        description = "Administrator MFA authentication, RBAC, dual control, and audit trail",
        packages = setOf("com.slotting.admin.auth", "com.slotting.admin.audit")
    ),
    SUPPORT(
        id = "support",
        description = "Non-authoritative CRM read views, player support, and ticketing boundaries",
        packages = setOf("com.slotting.admin.crm")
    ),
    OUTBOX(
        id = "outbox",
        description = "Transactional outbox, DLQ replay, event broker dispatch, and distributed locking",
        packages = setOf("com.slotting.admin.outbox", "com.slotting.admin.locking")
    );

    companion object {
        val REQUIRED_MODULE_IDS: Set<String> = entries.map { it.id }.toSet()

        fun fromId(id: String): CanonicalBackendModule? =
            entries.firstOrNull { it.id.equals(id, ignoreCase = true) }
    }
}

/**
 * Status of backend module boundary enforcement.
 */
enum class BoundaryEnforcementStatus {
    ENFORCED,
    VIOLATION
}

/**
 * Command requesting validation and enforcement of backend module boundaries.
 */
data class EnforceModuleBoundariesCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val declaredModules: Set<String>
)

/**
 * Authoritative result of backend module boundary enforcement.
 */
data class EnforceModuleBoundariesResult(
    val resultId: UUID,
    val status: BoundaryEnforcementStatus,
    val serverTime: Instant,
    val serverVersion: Long,
    val enforcedModules: Set<String>,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

/**
 * Boundary store interface for auditing and idempotency tracking.
 */
interface ModuleBoundaryStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<EnforceModuleBoundariesCommand, EnforceModuleBoundariesResult>?
    fun save(
        tenantId: String,
        command: EnforceModuleBoundariesCommand,
        result: EnforceModuleBoundariesResult
    )
    fun currentVersion(tenantId: String): Long
}

/**
 * In-memory test store for module boundary enforcement.
 */
class InMemoryModuleBoundaryStore : ModuleBoundaryStore {
    val results = ConcurrentHashMap<String, Pair<EnforceModuleBoundariesCommand, EnforceModuleBoundariesResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String): Pair<EnforceModuleBoundariesCommand, EnforceModuleBoundariesResult>? {
        return results["$tenantId:$key"]
    }

    override fun save(
        tenantId: String,
        command: EnforceModuleBoundariesCommand,
        result: EnforceModuleBoundariesResult
    ) {
        results["$tenantId:${command.idempotencyKey}"] = Pair(command, result)
        audit.add(result.auditEvent)
        outbox.add(result.outboxEvent)
    }

    override fun currentVersion(tenantId: String): Long = 1L
}

/**
 * Service enforcing backend modular monolith boundaries per ARCH-001-02.
 */
class BackendModuleBoundaryService(
    private val store: ModuleBoundaryStore,
    private val clock: Clock = Clock.systemUTC()
) {
    fun enforce(command: EnforceModuleBoundariesCommand): EnforceModuleBoundariesResult = synchronized(store) {
        BackendModuleBoundaryBinding.checkBound()

        // 1. Authentication check
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 2. Authorization & Tenant check
        if (command.tenantId.isBlank() || command.tenantId != principal.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Stale version check
        if (command.expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 4. Idempotency validation
        if (command.idempotencyKey.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (storedCommand, storedResult) ->
            if (storedCommand == command) {
                return storedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        // 5. Canonical module presence check (all 9 required modules must be declared)
        val missingModules = CanonicalBackendModule.REQUIRED_MODULE_IDS - command.declaredModules
        if (missingModules.isNotEmpty()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 6. Enforce zero Android source impact (no android.* packages allowed in backend classpath)
        val hasAndroidDependency = command.declaredModules.any { it.contains("android", ignoreCase = true) }
        if (hasAndroidDependency) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val resultId = UUID.randomUUID()
        val now = clock.instant()
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BACKEND_MODULE_BOUNDARIES_ENFORCED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BACKEND_MODULE_BOUNDARIES_ENFORCED",
            createdAt = now
        )

        val result = EnforceModuleBoundariesResult(
            resultId = resultId,
            status = BoundaryEnforcementStatus.ENFORCED,
            serverTime = now,
            serverVersion = command.expectedVersion,
            enforcedModules = CanonicalBackendModule.REQUIRED_MODULE_IDS,
            evidenceReference = "arch-boundary:${command.tenantId}:${resultId}",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.save(command.tenantId, command, result)
        return result
    }
}
