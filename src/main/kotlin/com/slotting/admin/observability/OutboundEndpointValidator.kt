package com.slotting.admin.observability

import java.net.URI
import java.net.InetAddress
import java.net.Inet4Address

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
        if (url.isNullOrBlank()) throw ObservabilitySsrfException("Outbound endpoint URL is required")

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
        if (uri.userInfo != null || uri.rawFragment != null) {
            throw ObservabilitySsrfException("Outbound endpoint must not contain credentials or fragments")
        }
        val lowerHost = host.lowercase().trimEnd('.')
        if (isNonStandardNumericHost(lowerHost)) {
            throw ObservabilitySsrfException("Non-standard numeric IP spelling is prohibited")
        }

        // Explicit check for cloud metadata
        if (lowerHost == "169.254.169.254" || lowerHost.contains("metadata.google.internal") || lowerHost.contains("metadata.aws")) {
            throw ObservabilitySsrfException("Access to cloud metadata service is prohibited: $host")
        }

        if (lowerHost == "localhost" || lowerHost.endsWith(".localhost")) {
            throw ObservabilitySsrfException("Local destination '$host' is forbidden")
        }

        try {
            val addresses = InetAddress.getAllByName(host)
            if (addresses.isEmpty()) throw ObservabilitySsrfException("Endpoint host '$host' resolved to no addresses")
            for (addr in addresses) {
                if (isNonPublicAddress(addr)) throw ObservabilitySsrfException("Resolved non-public address is forbidden")
            }
        } catch (e: Exception) {
            if (e is ObservabilitySsrfException) throw e
            throw ObservabilityValidationException("Cannot resolve endpoint host '$host'")
        }
    }

    private fun isNonPublicAddress(address: InetAddress): Boolean {
        val bytes = address.address.map { it.toInt() and 0xFF }
        if (address.isAnyLocalAddress || address.isLoopbackAddress || address.isLinkLocalAddress ||
            address.isSiteLocalAddress || address.isMulticastAddress) return true
        if (address is Inet4Address) {
            val first = bytes[0]
            val second = bytes[1]
            val third = bytes[2]
            return first == 0 || first == 10 || first == 127 || first >= 224 ||
                (first == 100 && second in 64..127) ||
                (first == 169 && second == 254) ||
                (first == 172 && second in 16..31) ||
                (first == 192 && second == 168) ||
                (first == 192 && second == 0 && third == 0) ||
                (first == 192 && second == 0 && third == 2) ||
                (first == 198 && second in 18..19) ||
                (first == 198 && second == 51 && third == 100) ||
                (first == 203 && second == 0 && third == 113)
        }
        if (bytes.size == 16 && bytes.take(10).all { it == 0 } && bytes[10] == 0xFF && bytes[11] == 0xFF) {
            val mapped = InetAddress.getByAddress(bytes.drop(12).map { it.toByte() }.toByteArray())
            return isNonPublicAddress(mapped)
        }
        return bytes[0] and 0xFE == 0xFC || bytes[0] == 0xFF ||
            (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0D && bytes[3] == 0xB8)
    }

    private fun isNonStandardNumericHost(host: String): Boolean {
        val standardIpv4 = host.split('.').let { parts ->
            parts.size == 4 && parts.all { part ->
                part.isNotEmpty() && (part == "0" || !part.startsWith('0')) &&
                    part.all(Char::isDigit) && part.toIntOrNull()?.let { it in 0..255 } == true
            }
        }
        if (standardIpv4) return false
        return host.startsWith("0x") || host.all(Char::isDigit) ||
            host.matches(Regex("(?i)(?:0x[0-9a-f]+|0[0-7]+|[0-9]+)(?:\\.(?:0x[0-9a-f]+|0[0-7]+|[0-9]+)){0,3}"))
    }
}
