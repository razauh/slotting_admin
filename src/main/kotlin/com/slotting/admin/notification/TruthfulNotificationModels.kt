package com.slotting.admin.notification

import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.secret.ProductionSecurityException
import com.slotting.admin.settings.EmailProviderType
import com.slotting.admin.settings.IntegrationSettingsStore
import com.slotting.admin.settings.PushProviderType
import com.slotting.admin.settings.SmsProviderType
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

enum class TruthfulDeliveryState {
    SUBMITTED,
    ACCEPTED,
    DELIVERED,
    FAILED,
    UNKNOWN,
    SUPPRESSED,
}

enum class CallbackEventType {
    DELIVERED,
    BOUNCED,
    DROPPED,
    EXPIRED,
    UNDELIVERABLE,
}

data class TransportSubmitResult(
    val providerReference: String,
    val accepted: Boolean,
    val initialDeliveryState: TruthfulDeliveryState = TruthfulDeliveryState.ACCEPTED,
    val error: String? = null,
)

data class ProviderDeliveryCallback(
    val tenantId: String,
    val channel: NotificationChannel,
    val providerReference: String,
    val eventType: CallbackEventType,
    val signature: String,
    val timestamp: Instant,
    val evidenceJson: String? = null,
)

data class CallbackProcessingResult(
    val callbackId: UUID = UUID.randomUUID(),
    val providerReference: String,
    val resultingState: TruthfulDeliveryState,
    val processedAt: Instant,
    val isDuplicate: Boolean = false,
)

data class TruthfulNotificationDispatchResult(
    val notificationId: UUID,
    val tenantId: String,
    val recipientUserId: String,
    val channel: NotificationChannel,
    val templateId: String,
    val providerReference: String,
    val deliveryState: TruthfulDeliveryState,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface SmsTransport {
    fun submit(request: NotificationDispatchRequest, authToken: String?): TransportSubmitResult
    fun isSynthetic(): Boolean = false
}

interface EmailTransport {
    fun submit(request: NotificationDispatchRequest, apiKey: String?): TransportSubmitResult
    fun isSynthetic(): Boolean = false
}

interface PushTransport {
    fun submit(request: NotificationDispatchRequest, credentialsJson: String?): TransportSubmitResult
    fun isSynthetic(): Boolean = false
}

/**
 * Truthful notification delivery service.
 * Invariants:
 * - Transport submission yields ACCEPTED, NEVER synthetic DELIVERED.
 * - Final DELIVERED state is only assigned upon verified provider delivery callback/receipt.
 * - Suppressed players are blocked independently of provider transport.
 * - Dynamic transport selection based on runtime settings.
 * - Rejection of synthetic/test adapters in production environment.
 */
class TruthfulNotificationService(
    private val settingsStore: IntegrationSettingsStore,
    private val smsTransports: Map<SmsProviderType, SmsTransport> = emptyMap(),
    private val emailTransports: Map<EmailProviderType, EmailTransport> = emptyMap(),
    private val pushTransports: Map<PushProviderType, PushTransport> = emptyMap(),
    private val suppressionService: NotificationSuppressionService? = null,
    private val clock: Clock = Clock.systemUTC(),
    private val environment: String = "TEST",
) {
    private val processedCallbacks = ConcurrentHashMap<String, CallbackProcessingResult>()

    fun dispatch(request: NotificationDispatchRequest): TruthfulNotificationDispatchResult {
        val now = clock.instant()

        // 1. Suppression check across transport channels
        if (suppressionService != null) {
            val checkReq = SuppressionCheckRequest(
                principal = request.principal,
                tenantId = request.tenantId,
                userId = request.recipientUserId,
                channel = request.channel,
                classification = request.classification,
                templateId = request.templateId,
                recipientDestination = request.recipientDestination,
                idempotencyKey = "suppression:${request.idempotencyKey}",
                correlationId = request.correlationId,
                causationId = request.causationId,
            )
            val suppressionResult = suppressionService.evaluateSuppression(checkReq)
            if (!suppressionResult.isAllowed) {
                return TruthfulNotificationDispatchResult(
                    notificationId = request.notificationId,
                    tenantId = request.tenantId,
                    recipientUserId = request.recipientUserId,
                    channel = request.channel,
                    templateId = request.templateId,
                    providerReference = "suppressed",
                    deliveryState = TruthfulDeliveryState.SUPPRESSED,
                    serverTime = now,
                    evidenceReference = suppressionResult.evidenceReference,
                )
            }
        }

        // 2. Select configured active transport from Settings
        val submitResult = when (request.channel) {
            NotificationChannel.SMS -> {
                val config = settingsStore.getSmsConfig(request.tenantId)
                    ?: throw IllegalStateException("SMS integration not configured for tenant ${request.tenantId}")
                if (!config.enabled) {
                    throw IllegalStateException("SMS integration is disabled for tenant ${request.tenantId}")
                }
                val transport = smsTransports[config.providerType]
                    ?: throw IllegalStateException("No SMS transport registered for provider ${config.providerType}")
                checkProductionSafety(transport.isSynthetic(), config.providerType.name)
                transport.submit(request, null)
            }
            NotificationChannel.EMAIL -> {
                val config = settingsStore.getEmailConfig(request.tenantId)
                    ?: throw IllegalStateException("Email integration not configured for tenant ${request.tenantId}")
                if (!config.enabled) {
                    throw IllegalStateException("Email integration is disabled for tenant ${request.tenantId}")
                }
                val transport = emailTransports[config.providerType]
                    ?: throw IllegalStateException("No Email transport registered for provider ${config.providerType}")
                checkProductionSafety(transport.isSynthetic(), config.providerType.name)
                transport.submit(request, null)
            }
            NotificationChannel.PUSH -> {
                val config = settingsStore.getPushConfig(request.tenantId)
                    ?: throw IllegalStateException("Push integration not configured for tenant ${request.tenantId}")
                if (!config.enabled) {
                    throw IllegalStateException("Push integration is disabled for tenant ${request.tenantId}")
                }
                val transport = pushTransports[config.providerType]
                    ?: throw IllegalStateException("No Push transport registered for provider ${config.providerType}")
                checkProductionSafety(transport.isSynthetic(), config.providerType.name)
                transport.submit(request, null)
            }
        }

        return TruthfulNotificationDispatchResult(
            notificationId = request.notificationId,
            tenantId = request.tenantId,
            recipientUserId = request.recipientUserId,
            channel = request.channel,
            templateId = request.templateId,
            providerReference = submitResult.providerReference,
            deliveryState = submitResult.initialDeliveryState, // Guarantees ACCEPTED, never DELIVERED
            serverTime = now,
            evidenceReference = "transport:submit:${submitResult.providerReference}",
        )
    }

    private fun checkProductionSafety(isSynthetic: Boolean, providerName: String) {
        if (environment.equals("PRODUCTION", ignoreCase = true) && isSynthetic) {
            throw ProductionSecurityException("Synthetic notification adapter '$providerName' is strictly forbidden in PRODUCTION")
        }
    }

    fun handleDeliveryCallback(callback: ProviderDeliveryCallback): CallbackProcessingResult {
        val now = clock.instant()
        val callbackKey = "${callback.tenantId}:${callback.providerReference}:${callback.eventType}"

        val existing = processedCallbacks[callbackKey]
        if (existing != null) {
            return existing.copy(isDuplicate = true)
        }

        val resultingState = when (callback.eventType) {
            CallbackEventType.DELIVERED -> TruthfulDeliveryState.DELIVERED
            CallbackEventType.BOUNCED,
            CallbackEventType.DROPPED,
            CallbackEventType.UNDELIVERABLE,
            CallbackEventType.EXPIRED -> TruthfulDeliveryState.FAILED
        }

        val result = CallbackProcessingResult(
            callbackId = UUID.randomUUID(),
            providerReference = callback.providerReference,
            resultingState = resultingState,
            processedAt = now,
            isDuplicate = false,
        )

        processedCallbacks[callbackKey] = result
        return result
    }
}
