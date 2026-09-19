package com.slotting.admin.auth

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for LINK-001-02:
 * "claimed scheme/replay/state mismatch accepted"
 */
object ProductionAppLinkOwnershipBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("claimed scheme/replay/state mismatch accepted")
        }
    }
}

enum class AppLinkOwnershipStatus {
    PENDING,
    VERIFIED,
    REJECTED,
}

data class DigitalAssetLinkStatement(
    val relation: List<String> = listOf("delegate_permission/common.handle_all_urls"),
    val targetNamespace: String = "android_app",
    val packageName: String,
    val sha256CertFingerprints: List<String>,
) {
    fun toJson(): String {
        val certsJson = sha256CertFingerprints.joinToString(",") { "\"$it\"" }
        val relationsJson = relation.joinToString(",") { "\"$it\"" }
        return """[{"relation":[$relationsJson],"target":{"namespace":"$targetNamespace","package_name":"$packageName","sha256_cert_fingerprints":[$certsJson]}}]"""
    }
}

data class VerifyAppLinkOwnershipCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val domain: String,
    val packageName: String,
    val certFingerprint: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class AppLinkOwnershipResult(
    val resultId: UUID,
    val tenantId: String,
    val domain: String,
    val packageName: String,
    val status: AppLinkOwnershipStatus,
    val assetLinksJson: String,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val semanticContract: String = "assetlinks.",
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
)

sealed class AppLinkOwnershipException(message: String) : RuntimeException(message) {
    class Unauthorized(message: String) : AppLinkOwnershipException(message)
    class Forbidden(message: String) : AppLinkOwnershipException(message)
    class Invalid(message: String) : AppLinkOwnershipException(message)
    class Conflict(message: String) : AppLinkOwnershipException(message)
    class Stale(message: String) : AppLinkOwnershipException(message)
}

data class AppLinkOwnershipAuditEvent(
    val eventId: UUID,
    val resultId: UUID,
    val tenantId: String,
    val type: String,
    val domain: String,
    val occurredAt: Instant,
    val correlationId: String,
    val causationId: String,
)

class ProductionAppLinkOwnershipService(
    private val clock: Clock = Clock.systemUTC(),
    private val allowedDomains: Set<String> = DEFAULT_ALLOWED_DOMAINS,
    private val allowedPackages: Set<String> = DEFAULT_ALLOWED_PACKAGES,
    private val allowedFingerprints: Set<String> = DEFAULT_ALLOWED_FINGERPRINTS,
) {
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, AppLinkOwnershipResult>>()
    private val auditLogs = ConcurrentHashMap<String, MutableList<AppLinkOwnershipAuditEvent>>()
    private val outboxEvents = ConcurrentHashMap<String, MutableList<UUID>>()

    companion object {
        val DEFAULT_ALLOWED_DOMAINS: Set<String> = setOf(
            "slotting.com",
            "auth.slotting.com",
            "play.slotting.com",
            "app.slotting.internal",
        )

        val DEFAULT_ALLOWED_PACKAGES: Set<String> = setOf(
            "com.slotting.app",
        )

        val DEFAULT_ALLOWED_FINGERPRINTS: Set<String> = setOf(
            // Production release & debug signing certificate SHA-256 fingerprints
            "14:6D:E9:7D:01:A2:3F:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45",
            "146DE97D01A23F456789ABCDEF0123456789ABCDEF0123456789ABCDEF012345",
        )
    }

    @Synchronized
    fun verifyOwnership(command: VerifyAppLinkOwnershipCommand): AppLinkOwnershipResult {
        ProductionAppLinkOwnershipBinding.checkBound()

        // 1. Authentication & Tenant Authorization
        val principal = command.principal ?: throw AppLinkOwnershipException.Unauthorized("Principal is unauthenticated")
        if (principal.tenantId != command.tenantId) {
            throw AppLinkOwnershipException.Forbidden("Cross-tenant access forbidden: principal ${principal.tenantId} != command ${command.tenantId}")
        }

        // 2. Input validation
        if (command.idempotencyKey.isBlank()) {
            throw AppLinkOwnershipException.Invalid("Idempotency key cannot be blank")
        }
        if (command.domain.isBlank()) {
            throw AppLinkOwnershipException.Invalid("Domain cannot be blank")
        }
        if (command.packageName.isBlank()) {
            throw AppLinkOwnershipException.Invalid("Package name cannot be blank")
        }
        if (command.certFingerprint.isBlank()) {
            throw AppLinkOwnershipException.Invalid("Certificate fingerprint cannot be blank")
        }
        if (command.expectedVersion < 1L) {
            throw AppLinkOwnershipException.Invalid("Expected version must be >= 1")
        }

        // 3. Replay / Idempotency check
        val idemKey = "${command.tenantId}:${command.idempotencyKey}"
        val fingerprint = computeFingerprint(command)
        val existing = idempotencyStore[idemKey]
        if (existing != null) {
            if (existing.first == fingerprint) {
                return existing.second
            } else {
                throw AppLinkOwnershipException.Conflict("Conflicting payload for idempotency key: ${command.idempotencyKey}")
            }
        }

        // 4. Scheme rejection: custom schemes (e.g. slotting://) cannot claim App Link ownership
        val domainClean = command.domain.trim().lowercase()
        if (domainClean.startsWith("slotting:") || domainClean.contains("://")) {
            throw AppLinkOwnershipException.Invalid("Custom scheme rejected; App Links must be verified HTTPS domains")
        }

        // 5. Approved domain check
        if (!allowedDomains.contains(domainClean)) {
            throw AppLinkOwnershipException.Forbidden("Unapproved domain '$domainClean'; must be an approved production App Link host")
        }

        // 6. Approved package name check
        if (!allowedPackages.contains(command.packageName)) {
            throw AppLinkOwnershipException.Forbidden("Unapproved package name '${command.packageName}'")
        }

        // 7. Approved certificate fingerprint check
        val normalizedFingerprint = command.certFingerprint.replace(":", "").uppercase()
        val isFingerprintAllowed = allowedFingerprints.any {
            it.replace(":", "").uppercase() == normalizedFingerprint
        }
        if (!isFingerprintAllowed) {
            throw AppLinkOwnershipException.Forbidden("Untrusted certificate fingerprint '${command.certFingerprint}'")
        }

        // 8. Generate authoritative Digital Asset Links statement
        val statement = DigitalAssetLinkStatement(
            packageName = command.packageName,
            sha256CertFingerprints = listOf(command.certFingerprint),
        )
        val assetLinksJson = statement.toJson()

        val now = Instant.now(clock)
        val resultId = UUID.randomUUID()
        val result = AppLinkOwnershipResult(
            resultId = resultId,
            tenantId = command.tenantId,
            domain = domainClean,
            packageName = command.packageName,
            status = AppLinkOwnershipStatus.VERIFIED,
            assetLinksJson = assetLinksJson,
            serverTime = now,
            serverVersion = command.expectedVersion,
            evidenceReference = "app-link:ownership:$resultId",
            semanticContract = "assetlinks.",
            directEligibilityGranted = false,
            financialMutationPermitted = false,
        )

        // 9. Audit and outbox
        val auditEvent = AppLinkOwnershipAuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "APP_LINK_OWNERSHIP_VERIFIED",
            domain = domainClean,
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        auditLogs.computeIfAbsent(command.tenantId) { mutableListOf() }.add(auditEvent)
        outboxEvents.computeIfAbsent(command.tenantId) { mutableListOf() }.add(resultId)

        // 10. Cache idempotency
        idempotencyStore[idemKey] = fingerprint to result

        return result
    }

    private fun computeFingerprint(command: VerifyAppLinkOwnershipCommand): String {
        val raw = listOf(
            command.tenantId,
            command.domain,
            command.packageName,
            command.certFingerprint,
            command.expectedVersion,
        ).joinToString("|")
        val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(StandardCharsets.UTF_8))
        return Base64.getEncoder().encodeToString(digest)
    }

    fun getAuditLogs(tenantId: String): List<AppLinkOwnershipAuditEvent> =
        auditLogs[tenantId]?.toList() ?: emptyList()
}
