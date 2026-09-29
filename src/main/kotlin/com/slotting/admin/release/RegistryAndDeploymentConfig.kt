package com.slotting.admin.release

import org.slf4j.LoggerFactory
import java.time.Instant

/**
 * Provider-neutral OCI Registry Configuration (Harbor preferred) (TC-041).
 * Credentials are write-only from administrative UI and redacted from audit trails.
 */
data class RegistryConfiguration(
    val provider: String = "HARBOR",
    val endpoint: String,
    val project: String,
    val username: String,
    val secretToken: String,
) {
    fun toSafeAuditDetails(): Map<String, String> {
        return mapOf(
            "provider" to provider,
            "endpoint" to endpoint,
            "project" to project,
            "username" to username,
            "secretToken" to "[REDACTED]",
        )
    }
}

/**
 * Provider-neutral Deployment Target Adapter (TC-041).
 * Decouples release gating from specific orchestrator implementations (Kubernetes, Nomad, VMs).
 */
interface DeploymentTargetAdapter {
    fun deployWorkload(environment: Environment, artifactDigest: String, config: Map<String, String>): Boolean
    fun checkHealth(environment: Environment, workloadId: String): Boolean
    fun rollbackWorkload(environment: Environment, targetDigest: String): Boolean
}

/**
 * Structured, secret-sanitizing audit logger for release and promotion actions (TC-041).
 */
class ReleaseAuditLogger {

    private val log = LoggerFactory.getLogger(javaClass)

    fun formatAuditLog(
        action: String,
        details: Map<String, String>,
        actor: String,
        occurredAt: Instant = Instant.now(),
    ): String {
        // Redact any accidental secret keys
        val sanitizedDetails = details.mapValues { (k, v) ->
            if (k.contains("token", ignoreCase = true) ||
                k.contains("secret", ignoreCase = true) ||
                k.contains("password", ignoreCase = true) ||
                k.contains("key", ignoreCase = true)
            ) {
                if (v == "[REDACTED]") v else "[REDACTED]"
            } else {
                v
            }
        }

        val formatted = "RELEASE_AUDIT timestamp=$occurredAt action=$action actor=$actor details=$sanitizedDetails"
        log.info(formatted)
        return formatted
    }
}
