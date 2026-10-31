package com.slotting.admin.provider

import com.slotting.admin.provider.port.ProviderConfiguration
import com.slotting.admin.provider.port.ProviderEnvironment
import com.slotting.admin.provider.port.ProviderHttpClient
import java.net.URI
import java.time.Clock
import java.time.Instant

data class ProviderProbeRequest(
    val tenantId: String,
    val providerId: String,
    val environment: ProviderEnvironment,
    val endpointUrl: String,
    val configVersion: Long,
    val credentialsAvailable: Boolean,
    val allowLoopbackForTest: Boolean = false,
)

data class ProviderProbeResult(
    val status: ProviderProbeStatus,
    val checkedAt: Instant,
    val environment: ProviderEnvironment,
    val configVersion: Long,
    val safeMessage: String,
)

object ProviderEndpointPolicy {
    private val blockedHosts = setOf(
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "169.254.169.254",
        "metadata.google.internal",
    )

    fun assertAllowed(baseUrl: String, environment: ProviderEnvironment, allowLoopbackForTest: Boolean) {
        val uri = try {
            URI.create(baseUrl)
        } catch (e: Exception) {
            throw IllegalArgumentException("Invalid provider endpoint")
        }
        require(uri.userInfo == null) { "Provider endpoint must not contain user information" }
        val host = uri.host?.lowercase() ?: throw IllegalArgumentException("Provider endpoint missing host")
        if (!allowLoopbackForTest) {
            require(host !in blockedHosts) { "Provider endpoint host is not allowed" }
            require(!host.startsWith("127.") && !host.startsWith("10.") && !host.startsWith("192.168.")) {
                "Provider endpoint host is not allowed"
            }
            val secondOctet = host.split(".").getOrNull(1)?.toIntOrNull()
            require(!(host.startsWith("172.") && secondOctet in 16..31)) {
                "Provider endpoint host is not allowed"
            }
            val resolved = try {
                java.net.InetAddress.getAllByName(host)
            } catch (_: Exception) {
                throw IllegalArgumentException("Provider endpoint host cannot be resolved")
            }
            require(resolved.isNotEmpty() && resolved.all { address ->
                !address.isLoopbackAddress && !address.isSiteLocalAddress && !address.isLinkLocalAddress &&
                    !address.isAnyLocalAddress && !address.isMulticastAddress
            }) { "Provider endpoint resolves to a disallowed address" }
        }
        if (environment == ProviderEnvironment.PRODUCTION) {
            require(uri.scheme.equals("https", ignoreCase = true)) {
                "Production provider endpoint must use HTTPS"
            }
        }
    }
}

class ProviderConnectivityService(
    private val httpClient: ProviderHttpClient = ProviderHttpClient(),
    private val clock: Clock = Clock.systemUTC(),
    private val probePaths: Map<String, String> = emptyMap(),
) {
    fun probe(request: ProviderProbeRequest): ProviderProbeResult {
        val now = clock.instant()
        val definition = ProviderCatalogue.find(request.providerId)
        if (definition == null || request.configVersion <= 0L || request.endpointUrl.isBlank()) {
            return result(ProviderProbeStatus.INVALID_CONFIG, now, request, "Provider configuration is incomplete")
        }
        if (!request.credentialsAvailable) {
            return result(ProviderProbeStatus.INVALID_CONFIG, now, request, "Provider credentials are missing")
        }
        val probePath = probePaths[request.providerId.uppercase()]?.takeIf { it.isNotBlank() }
            ?: return result(
                ProviderProbeStatus.NOT_VERIFIED,
                now,
                request,
                "No documented nonfinancial read operation is available for this provider",
            )
        try {
            ProviderEndpointPolicy.assertAllowed(request.endpointUrl, request.environment, request.allowLoopbackForTest)
        } catch (_: Exception) {
            return result(ProviderProbeStatus.INVALID_CONFIG, now, request, "Provider endpoint is not allowed")
        }
        val config = ProviderConfiguration(
            providerId = definition.providerId,
            environment = request.environment,
            baseUrl = request.endpointUrl,
            timeoutMs = 2_000L,
            maxRetries = 0,
        )
        return try {
            config.validateNetworkSafety()
            val response = httpClient.execute(config, "GET", probePath)
            when {
                response.statusCode in 200..299 -> result(ProviderProbeStatus.READY, now, request, "Provider read-only probe succeeded")
                response.statusCode == 401 || response.statusCode == 403 ->
                    result(ProviderProbeStatus.UNAUTHORIZED, now, request, "Provider rejected the configured credentials")
                else -> result(ProviderProbeStatus.UNREACHABLE, now, request, "Provider probe returned an unexpected status")
            }
        } catch (_: Exception) {
            result(ProviderProbeStatus.UNREACHABLE, now, request, "Provider probe could not reach the endpoint")
        }
    }

    private fun result(
        status: ProviderProbeStatus,
        now: Instant,
        request: ProviderProbeRequest,
        message: String,
    ) = ProviderProbeResult(
        status = status,
        checkedAt = now,
        environment = request.environment,
        configVersion = request.configVersion,
        safeMessage = message,
    )
}
