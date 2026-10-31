package com.slotting.admin.provider

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.provider.port.ProviderEnvironment
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

data class AdminProviderView(
    val providerId: String,
    val displayName: String,
    val environment: String,
    val status: String,
    val setupStatus: String,
    val endpointUrl: String,
    val walletCurrencies: Set<String>,
    val settlementCurrencies: Set<String>,
    val supportedOperations: Set<String>,
    val capabilityVersion: Long,
    val serverVersion: Long,
    val credentialVersion: Long,
    val permittedUseApproved: Boolean,
    val technicalVerificationApproved: Boolean,
    val externalEvidenceReference: String?,
    val reviewer: String?,
    val incidentReference: String?,
    val lastProbeStatus: String?,
    val lastProbeAt: String?,
    val maskedCredential: String = "********",
)

data class AdminProviderMutationRequest(
    val action: String,
    val displayName: String = "",
    val endpointUrl: String = "",
    val environment: String = "SANDBOX",
    val walletCurrencies: Set<String> = setOf("PKR"),
    val settlementCurrencies: Set<String> = setOf("PKR"),
    val supportedOperations: Set<String> = setOf("DEPOSIT"),
    val capabilityVersion: Long = 1L,
    val expectedVersion: Long = 0L,
    val incidentReference: String? = null,
    val permittedUseApproved: Boolean = false,
    val technicalVerificationApproved: Boolean = false,
    val externalEvidenceReference: String? = null,
    val reviewer: String? = null,
    val adapterProductionReady: Boolean = false,
    val merchantId: String? = null,
    val clientId: String? = null,
    val clientSecret: String? = null,
    val apiKeySecret: String? = null,
    val signingSecretOrKey: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class AdminProviderProbeRequest(
    val documentedProbePath: String? = null,
    val expectedVersion: Long,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

@RestController
@RequestMapping("/admin/payment-providers")
class AdminPaymentProviderController(
    private val service: PaymentProviderConfigService,
    private val connectivityService: ProviderConnectivityService = ProviderConnectivityService(),
    private val csrfTokens: AdminCsrfTokenService = AdminCsrfTokenService(),
) {

    @GetMapping
    fun listProviders(
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        val admin = principal ?: return unauthorized()
        if (!canRead(admin)) return forbidden()
        return try {
            ResponseEntity.ok(service.listProviders(admin.tenantId).map { it.toView() })
        } catch (e: AuthenticationFailure.Rejected) {
            failure(e)
        }
    }

    @GetMapping("/csrf")
    fun csrfToken(
        @RequestHeader(name = "X-Session-Id", required = false) sessionId: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        val admin = principal ?: return unauthorized()
        if (sessionId.isNullOrBlank()) return ResponseEntity.badRequest().body(mapOf("error" to "SESSION_REQUIRED"))
        return ResponseEntity.ok(mapOf("csrfToken" to csrfTokens.issue(sessionId, admin.id)))
    }

    @GetMapping("/{providerId}")
    fun getProvider(
        @PathVariable providerId: String,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        val admin = principal ?: return unauthorized()
        if (!canRead(admin)) return forbidden()
        val provider = service.listProviders(admin.tenantId).firstOrNull { it.providerId == providerId }
            ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body(mapOf("error" to "NOT_FOUND"))
        return ResponseEntity.ok(provider.toView())
    }

    @PostMapping("/{providerId}")
    fun mutate(
        @PathVariable providerId: String,
        @RequestBody request: AdminProviderMutationRequest,
        @RequestHeader(name = "X-Session-Id", required = false) sessionId: String?,
        @RequestHeader(name = "X-CSRF-Token", required = false) csrfToken: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        val admin = principal ?: return unauthorized()
        if (!csrfTokens.validate(sessionId, admin.id, csrfToken)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "CSRF_INVALID"))
        }
        val action = runCatching { PaymentProviderConfigAction.valueOf(request.action.uppercase()) }.getOrNull()
            ?: return ResponseEntity.badRequest().body(mapOf("error" to "INVALID_ACTION"))
        return try {
            val result = service.operate(
                PaymentProviderConfigCommand(
                    principal = admin,
                    sessionId = sessionId.orEmpty(),
                    tenantId = admin.tenantId,
                    providerId = providerId,
                    action = action,
                    displayName = request.displayName.ifBlank { providerId },
                    endpointUrl = request.endpointUrl,
                    apiKeySecret = request.apiKeySecret,
                    incidentReference = request.incidentReference,
                    idempotencyKey = request.idempotencyKey,
                    correlationId = request.correlationId,
                    causationId = request.causationId,
                    expectedVersion = request.expectedVersion,
                    environment = runCatching { ProviderEnvironment.valueOf(request.environment.uppercase()) }
                        .getOrDefault(ProviderEnvironment.SANDBOX),
                    walletCurrencies = request.walletCurrencies,
                    settlementCurrencies = request.settlementCurrencies,
                    supportedOperations = request.supportedOperations,
                    capabilityVersion = request.capabilityVersion,
                    permittedUseApproved = request.permittedUseApproved,
                    technicalVerificationApproved = request.technicalVerificationApproved,
                    externalEvidenceReference = request.externalEvidenceReference,
                    reviewer = request.reviewer,
                    merchantId = request.merchantId,
                    clientId = request.clientId,
                    clientSecret = request.clientSecret,
                    signingSecretOrKey = request.signingSecretOrKey,
                    adapterProductionReady = request.adapterProductionReady,
                )
            )
            ResponseEntity.ok(result.provider.toView())
        } catch (e: AuthenticationFailure.Rejected) {
            failure(e)
        }
    }

    @PostMapping("/{providerId}/probe")
    fun probe(
        @PathVariable providerId: String,
        @RequestBody request: AdminProviderProbeRequest,
        @RequestHeader(name = "X-Session-Id", required = false) sessionId: String?,
        @RequestHeader(name = "X-CSRF-Token", required = false) csrfToken: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        val admin = principal ?: return unauthorized()
        if (!csrfTokens.validate(sessionId, admin.id, csrfToken)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "CSRF_INVALID"))
        }
        val provider = service.listProviders(admin.tenantId).firstOrNull { it.providerId == providerId }
            ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body(mapOf("error" to "NOT_FOUND"))
        val probe = connectivityService.probe(
            ProviderProbeRequest(
                tenantId = admin.tenantId,
                providerId = providerId,
                environment = provider.environment,
                endpointUrl = provider.endpointUrl,
                configVersion = provider.serverVersion,
                credentialsAvailable = provider.credentialVersion > 0,
            )
        )
        return try {
            val result = service.operate(
                PaymentProviderConfigCommand(
                    principal = admin,
                    sessionId = sessionId.orEmpty(),
                    tenantId = admin.tenantId,
                    providerId = providerId,
                    action = PaymentProviderConfigAction.PROBE,
                    displayName = provider.displayName,
                    endpointUrl = provider.endpointUrl,
                    idempotencyKey = request.idempotencyKey,
                    correlationId = request.correlationId,
                    causationId = request.causationId,
                    expectedVersion = request.expectedVersion,
                    environment = provider.environment,
                    walletCurrencies = provider.walletCurrencies,
                    settlementCurrencies = provider.settlementCurrencies,
                    supportedOperations = provider.supportedOperations,
                    capabilityVersion = provider.capabilityVersion,
                    permittedUseApproved = provider.permittedUseApproved,
                    technicalVerificationApproved = provider.technicalVerificationApproved,
                    externalEvidenceReference = provider.externalEvidenceReference,
                    reviewer = provider.reviewer,
                    credentialVersion = provider.credentialVersion,
                    probeStatus = probe.status.name,
                )
            )
            ResponseEntity.ok(
                mapOf(
                    "status" to probe.status.name,
                    "checkedAt" to probe.checkedAt.toString(),
                    "environment" to probe.environment.name,
                    "configVersion" to probe.configVersion,
                    "providerVersion" to result.provider.serverVersion,
                    "message" to probe.safeMessage,
                )
            )
        } catch (e: AuthenticationFailure.Rejected) {
            failure(e)
        }
    }

    private fun PaymentProviderConfig.toView() = AdminProviderView(
        providerId = providerId,
        displayName = displayName,
        environment = environment.name,
        status = status.name,
        setupStatus = setupStatus.name,
        endpointUrl = endpointUrl,
        walletCurrencies = walletCurrencies,
        settlementCurrencies = settlementCurrencies,
        supportedOperations = supportedOperations,
        capabilityVersion = capabilityVersion,
        serverVersion = serverVersion,
        credentialVersion = credentialVersion,
        permittedUseApproved = permittedUseApproved,
        technicalVerificationApproved = technicalVerificationApproved,
        externalEvidenceReference = externalEvidenceReference,
        reviewer = reviewer,
        incidentReference = incidentReference,
        lastProbeStatus = lastProbeStatus,
        lastProbeAt = lastProbeAt?.toString(),
    )

    private fun canRead(principal: AuthenticatedPrincipal): Boolean =
        principal.kind == com.slotting.admin.auth.PrincipalKind.ADMIN &&
            principal.roles.any {
                it == com.slotting.admin.auth.AdminRole.SECURITY || it == com.slotting.admin.auth.AdminRole.SUPER_ADMIN
            }

    private fun forbidden(): ResponseEntity<Any> =
        ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "FORBIDDEN"))

    private fun unauthorized(): ResponseEntity<Any> =
        ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "UNAUTHENTICATED"))

    private fun failure(e: AuthenticationFailure.Rejected): ResponseEntity<Any> = when (e.code) {
        AuthErrorCode.UNAUTHENTICATED -> unauthorized()
        AuthErrorCode.FORBIDDEN -> ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "FORBIDDEN"))
        AuthErrorCode.STALE, AuthErrorCode.CONFLICT ->
            ResponseEntity.status(HttpStatus.CONFLICT).body(mapOf("error" to e.code.name, "instruction" to "Reload and retry"))
        AuthErrorCode.DEPENDENCY_UNAVAILABLE ->
            ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(mapOf("error" to "SERVICE_UNAVAILABLE"))
        else -> ResponseEntity.badRequest().body(mapOf("error" to e.code.name))
    }
}
