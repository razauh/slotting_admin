package com.slotting.admin.observability

import java.net.URI
import java.net.InetAddress

class ObservabilitySsrfException(message: String) : RuntimeException(message)
class ObservabilityValidationException(message: String) : RuntimeException(message)

object OutboundEndpointValidator {

    /**
     * Validates an outbound integration endpoint URL against SSRF vulnerabilities:
     * - Must be valid URI with HTTP/HTTPS scheme (HTTPS required in PRODUCTION)
     * - Rejects loopback (127.0.0.0/8, ::1, localhost) unless allowLocalDev is true
     * - Rejects cloud metadata (169.254.169.254, 169.254.0.0/16 link-local)
     * - Rejects non-HTTP(S) protocols (file, ftp, gopher, etc.)
     */
    fun validateEndpoint(
        url: String?,
        environment: String = "TEST",
        allowLocalDev: Boolean = false,
    ) {
        if (url.isNullOrBlank()) return

        val uri = try {
            URI.create(url.trim())
        } catch (e: Exception) {
            throw ObservabilitySsrfException("Invalid endpoint URI: ${e.message}")
        }

        val scheme = uri.scheme?.lowercase()
        if (scheme != "http" && scheme != "https") {
            throw ObservabilitySsrfException("Prohibited scheme '$scheme': only HTTP and HTTPS are permitted")
        }

        if (environment == "PRODUCTION" && scheme != "https") {
            throw ObservabilitySsrfException("Production integration endpoint must use HTTPS: $url")
        }

        val host = uri.host ?: throw ObservabilitySsrfException("Missing host in endpoint URI: $url")
        val lowerHost = host.lowercase()

        // Explicit check for cloud metadata
        if (lowerHost == "169.254.169.254" || lowerHost.contains("metadata.google.internal") || lowerHost.contains("metadata.aws")) {
            throw ObservabilitySsrfException("Access to cloud metadata service is prohibited: $host")
        }

        // Check loopback / localhost
        if (lowerHost == "localhost" || lowerHost == "127.0.0.1" || lowerHost == "::1") {
            if (environment == "PRODUCTION" || !allowLocalDev) {
                throw ObservabilitySsrfException("Loopback destination '$host' is forbidden in current environment")
            }
        }

        // Resolve host to inspect IP range
        try {
            val addresses = InetAddress.getAllByName(host)
            for (addr in addresses) {
                if (addr.isLoopbackAddress && (environment == "PRODUCTION" || !allowLocalDev)) {
                    throw ObservabilitySsrfException("Resolved loopback address ${addr.hostAddress} is forbidden")
                }
                if (addr.isLinkLocalAddress) {
                    throw ObservabilitySsrfException("Resolved link-local address ${addr.hostAddress} is forbidden")
                }
                if (addr.isAnyLocalAddress && (environment == "PRODUCTION" || !allowLocalDev)) {
                    throw ObservabilitySsrfException("Resolved any-local address ${addr.hostAddress} is forbidden")
                }
            }
        } catch (e: Exception) {
            if (e is ObservabilitySsrfException) throw e
            if (environment.equals("PRODUCTION", ignoreCase = true)) {
                throw ObservabilityValidationException("Cannot resolve endpoint host '$host': ${e.message}")
            }
        }
    }
}
