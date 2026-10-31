package com.slotting.admin.provider

import com.slotting.admin.auth.*
import com.slotting.admin.provider.port.ProviderCredentialWriter
import com.slotting.admin.provider.port.ProviderCredentials
import com.slotting.admin.provider.port.ProviderEnvironment
import com.slotting.admin.wallet.InvalidCurrencyException
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class PaymentProviderStatus { ENABLED, DISABLED, SUSPENDED }
enum class PaymentProviderConfigAction { REGISTER, UPDATE_CONFIG, ENABLE, DISABLE, ROTATE_CREDENTIAL, PROBE }

data class PaymentProviderConfigCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerId: String,
    val action: PaymentProviderConfigAction,
    val displayName: String,
    val endpointUrl: String,
    val apiKeySecret: String? = null,
    val incidentReference: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val environment: ProviderEnvironment = ProviderEnvironment.SANDBOX,
    val walletCurrencies: Set<String> = setOf("PKR"),
    val settlementCurrencies: Set<String> = setOf("PKR"),
    val supportedOperations: Set<String> = setOf("DEPOSIT"),
    val capabilityVersion: Long = 1L,
    val permittedUseApproved: Boolean = false,
    val technicalVerificationApproved: Boolean = false,
    val externalEvidenceReference: String? = null,
    val reviewer: String? = null,
    val credentialVersion: Long = 1L,
    val merchantId: String? = null,
    val clientId: String? = null,
    val clientSecret: String? = null,
    val signingSecretOrKey: String? = null,
    val adapterProductionReady: Boolean = false,
    val probeStatus: String? = null,
)

data class PaymentProviderConfig(
    val providerId: String,
    val displayName: String,
    val status: PaymentProviderStatus,
    val endpointUrl: String,
    val maskedSecretPreview: String,
    val incidentReference: String?,
    val serverVersion: Long,
    val environment: ProviderEnvironment = ProviderEnvironment.SANDBOX,
    val walletCurrencies: Set<String> = setOf("PKR"),
    val settlementCurrencies: Set<String> = setOf("PKR"),
    val supportedOperations: Set<String> = setOf("DEPOSIT"),
    val capabilityVersion: Long = 1L,
    val setupStatus: ProviderSetupState = ProviderSetupState.DISABLED,
    val permittedUseApproved: Boolean = false,
    val technicalVerificationApproved: Boolean = false,
    val externalEvidenceReference: String? = null,
    val reviewer: String? = null,
    val credentialVersion: Long = 0L,
    val lastProbeStatus: String? = null,
    val lastProbeAt: Instant? = null,
)

data class PaymentProviderConfigResult(
    val resultId: UUID,
    val provider: PaymentProviderConfig,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface PaymentProviderConfigStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<String, PaymentProviderConfigResult>?
    fun findProvider(tenantId: String, providerId: String): PaymentProviderConfig?
    fun listProviders(tenantId: String): List<PaymentProviderConfig> = emptyList()
    fun save(
        result: PaymentProviderConfigResult,
        tenantId: String,
        secretHash: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class PaymentProviderConfigService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: PaymentProviderConfigStore,
    private val clock: Clock = Clock.systemUTC(),
    private val credentialsResolver: ProviderCredentialWriter? = null,
    private val adapterRegistry: ProviderAdapterRegistry = ProviderAdapterRegistry(),
) {
    @Synchronized
    fun operate(command: PaymentProviderConfigCommand): PaymentProviderConfigResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (command.providerId.isBlank() || command.providerId.length > 128 ||
            command.displayName.isBlank() || command.displayName.length > 128 ||
            command.sessionId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank() ||
            command.idempotencyKey.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (!command.endpointUrl.startsWith("https://") && !command.endpointUrl.startsWith("http://")) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = Instant.now(clock)
        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }
        if (session == null || !session.active || !session.expiresAt.isAfter(now) ||
            !session.mfaVerified || (session.mfaExpiresAt != null && !session.mfaExpiresAt.isAfter(now)) ||
            (!policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY) &&
             !policy.isPermitted(principal, AdminPermission.PAYMENT_CONFIGURATION))
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val fingerprint = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { replay ->
            if (replay.first != fingerprint) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return replay.second
        }

        val definition = ProviderCatalogue.find(command.providerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        val walletCurrencies = try {
            ProviderCatalogue.validateWalletCurrencies(command.walletCurrencies)
        } catch (e: InvalidCurrencyException) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        val settlementCurrencies = try {
            ProviderCatalogue.validateSettlementCurrencies(definition, command.settlementCurrencies)
        } catch (e: InvalidCurrencyException) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.environment == ProviderEnvironment.PRODUCTION && !command.endpointUrl.startsWith("https://")) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val existing = store.findProvider(command.tenantId, command.providerId)
        val suppliedCredentials = credentialsFrom(command)
        val credentialVersion = when (command.action) {
            PaymentProviderConfigAction.REGISTER -> command.credentialVersion
            PaymentProviderConfigAction.ROTATE_CREDENTIAL -> (existing?.credentialVersion ?: 0L) + 1L
            else -> existing?.credentialVersion ?: 0L
        }
        val credentialsAvailable = (existing?.credentialVersion ?: 0L) > 0L ||
            suppliedCredentials != null || !command.apiKeySecret.isNullOrBlank()

        val setupState = ProviderSetupPolicy.state(
            provider = definition,
            environment = command.environment,
            walletCurrencies = walletCurrencies,
            settlementCurrencies = settlementCurrencies,
            operations = command.supportedOperations,
            credentialsAvailable = credentialsAvailable,
            permittedUseApproved = command.permittedUseApproved,
            technicalVerificationApproved = command.technicalVerificationApproved,
            adapterProductionReady = adapterRegistry.isProductionReady(definition.providerId),
        )

        var newCredentialVersion: Long? = null
        val (nextProvider, secretHash) = when (command.action) {
            PaymentProviderConfigAction.REGISTER -> {
                if (existing != null) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                newCredentialVersion = storeSuppliedCredentials(command, suppliedCredentials, credentialVersion, principal, now)
                PaymentProviderConfig(
                    providerId = definition.providerId,
                    displayName = command.displayName,
                    status = PaymentProviderStatus.DISABLED,
                    endpointUrl = command.endpointUrl,
                    maskedSecretPreview = "********",
                    incidentReference = command.incidentReference,
                    serverVersion = 1L,
                    environment = command.environment,
                    walletCurrencies = walletCurrencies,
                    settlementCurrencies = settlementCurrencies,
                    supportedOperations = command.supportedOperations.map { it.uppercase() }.toSet(),
                    capabilityVersion = command.capabilityVersion,
                    setupStatus = setupState,
                    permittedUseApproved = command.permittedUseApproved,
                    technicalVerificationApproved = command.technicalVerificationApproved,
                    externalEvidenceReference = command.externalEvidenceReference,
                    reviewer = command.reviewer,
                    credentialVersion = if (suppliedCredentials != null) credentialVersion else 0L,
                ) to ""
            }
            PaymentProviderConfigAction.ENABLE -> {
                val current = existing ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (current.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                if (current.status == PaymentProviderStatus.ENABLED) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                if (command.incidentReference.isNullOrBlank()) throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                if (current.setupStatus != ProviderSetupState.READY) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                }
                if (current.environment == ProviderEnvironment.PRODUCTION &&
                    (!current.permittedUseApproved || !current.technicalVerificationApproved ||
                        current.externalEvidenceReference.isNullOrBlank() || current.reviewer.isNullOrBlank() ||
                        !adapterRegistry.isProductionReady(current.providerId))
                ) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
                current.copy(
                    status = PaymentProviderStatus.ENABLED,
                    incidentReference = command.incidentReference,
                    serverVersion = current.serverVersion + 1,
                ) to ""
            }
            PaymentProviderConfigAction.DISABLE -> {
                val current = existing ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (current.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                if (current.status == PaymentProviderStatus.DISABLED) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                if (command.incidentReference.isNullOrBlank()) throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                current.copy(
                    status = PaymentProviderStatus.DISABLED,
                    incidentReference = command.incidentReference,
                    serverVersion = current.serverVersion + 1,
                ) to ""
            }
            PaymentProviderConfigAction.UPDATE_CONFIG -> {
                val current = existing ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (current.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                newCredentialVersion = storeSuppliedCredentials(command, suppliedCredentials, credentialVersion, principal, now)
                current.copy(
                    displayName = command.displayName,
                    endpointUrl = command.endpointUrl,
                    maskedSecretPreview = "********",
                    incidentReference = command.incidentReference ?: current.incidentReference,
                    serverVersion = current.serverVersion + 1,
                    environment = command.environment,
                    walletCurrencies = walletCurrencies,
                    settlementCurrencies = settlementCurrencies,
                    supportedOperations = command.supportedOperations.map { it.uppercase() }.toSet(),
                    capabilityVersion = command.capabilityVersion,
                    setupStatus = setupState,
                    permittedUseApproved = command.permittedUseApproved,
                    technicalVerificationApproved = command.technicalVerificationApproved,
                    externalEvidenceReference = command.externalEvidenceReference,
                    reviewer = command.reviewer,
                    credentialVersion = if (suppliedCredentials != null) credentialVersion else current.credentialVersion,
                    status = if (setupState == ProviderSetupState.READY) current.status else PaymentProviderStatus.DISABLED,
                ) to ""
            }
            PaymentProviderConfigAction.ROTATE_CREDENTIAL -> {
                val current = existing ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (current.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                if (suppliedCredentials == null) throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                newCredentialVersion = storeSuppliedCredentials(command, suppliedCredentials, credentialVersion, principal, now)
                current.copy(
                    maskedSecretPreview = "********",
                    serverVersion = current.serverVersion + 1,
                    credentialVersion = credentialVersion,
                ) to ""
            }
            PaymentProviderConfigAction.PROBE -> {
                val current = existing ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (current.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                val status = command.probeStatus?.uppercase()?.takeIf {
                    runCatching { ProviderProbeStatus.valueOf(it) }.isSuccess
                } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                current.copy(
                    lastProbeStatus = status,
                    lastProbeAt = now,
                    serverVersion = current.serverVersion + 1,
                ) to ""
            }
        }

        val resultId = UUID.randomUUID()
        val result = PaymentProviderConfigResult(
            resultId = resultId,
            provider = nextProvider,
            serverTime = now,
            evidenceReference = "provider-config:$resultId",
        )

        val type = "PROVIDER_CONFIG_${command.action.name}"
        val audit = AuditEvent(UUID.randomUUID(), resultId, command.tenantId, type, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), resultId, command.tenantId, type, now)
        try {
            store.save(result, command.tenantId, secretHash, fingerprint, command.idempotencyKey, audit, outbox)
        } catch (failure: Exception) {
            newCredentialVersion?.let { version ->
                runCatching { credentialsResolver?.revokeVersion(command.tenantId, command.providerId, version, now) }
            }
            throw failure
        }
        return result
    }

    fun listProviders(tenantId: String): List<PaymentProviderConfig> = store.listProviders(tenantId)

    private fun credentialsFrom(command: PaymentProviderConfigCommand): ProviderCredentials? {
        val credentials = ProviderCredentials(
            merchantId = command.merchantId,
            clientId = command.clientId,
            clientSecret = command.clientSecret,
            apiKey = command.apiKeySecret,
            signingSecretOrKey = command.signingSecretOrKey,
        )
        return credentials.takeIf {
            listOf(it.merchantId, it.clientId, it.clientSecret, it.apiKey, it.signingSecretOrKey).any { value -> !value.isNullOrBlank() } ||
                it.additionalProperties.isNotEmpty()
        }
    }

    private fun storeSuppliedCredentials(
        command: PaymentProviderConfigCommand,
        credentials: ProviderCredentials?,
        credentialVersion: Long,
        principal: AuthenticatedPrincipal,
        now: Instant,
    ): Long? {
        if (credentials == null) return null
        val resolver = credentialsResolver
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        try {
            resolver.storeCredentialsVersioned(
                tenantId = command.tenantId,
                providerId = command.providerId,
                secretKeyAlias = "provider-${command.providerId.lowercase()}-credentials",
                credentials = credentials,
                principal = principal,
                credentialVersion = credentialVersion,
                now = now,
            )
            resolver.activateVersion(command.tenantId, command.providerId, credentialVersion, now)
            return credentialVersion
        } catch (e: AuthenticationFailure.Rejected) {
            throw e
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }
    }

    private fun fingerprint(command: PaymentProviderConfigCommand): String = listOf(
        command.tenantId,
        command.providerId,
        command.action,
        command.displayName,
        command.endpointUrl,
        command.incidentReference,
        command.expectedVersion,
    ).joinToString("|") { sha256(it.toString()) }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}
