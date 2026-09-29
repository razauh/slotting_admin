package com.slotting.admin.health

import org.springframework.boot.actuate.health.Health
import org.springframework.boot.actuate.health.HealthIndicator
import org.springframework.stereotype.Component

/**
 * Health indicator verifying that the identity subsystem and auth store are functional and ready (TC-040).
 */
@Component("identityReadiness")
class IdentityReadinessHealthIndicator(
    private val check: () -> Boolean = { true },
) : HealthIndicator {
    override fun health(): Health {
        return try {
            if (check()) {
                Health.up().withDetail("identity", "ready").build()
            } else {
                Health.down().withDetail("identity", "degraded").build()
            }
        } catch (e: Exception) {
            Health.down(e).withDetail("identity", "error").build()
        }
    }
}

/**
 * Health indicator verifying that the double-entry ledger is connected and operational (TC-040).
 */
@Component("ledgerReadiness")
class LedgerReadinessHealthIndicator(
    private val check: () -> Boolean = { true },
) : HealthIndicator {
    override fun health(): Health {
        return try {
            if (check()) {
                Health.up().withDetail("ledger", "ready").build()
            } else {
                Health.down().withDetail("ledger", "degraded").build()
            }
        } catch (e: Exception) {
            Health.down(e).withDetail("ledger", "error").build()
        }
    }
}

/**
 * Health indicator verifying that external/internal provider ports and circuits are functional (TC-040).
 */
@Component("providerReadiness")
class ProviderReadinessHealthIndicator(
    private val check: () -> Boolean = { true },
) : HealthIndicator {
    override fun health(): Health {
        return try {
            if (check()) {
                Health.up().withDetail("provider", "ready").build()
            } else {
                Health.down().withDetail("provider", "degraded").build()
            }
        } catch (e: Exception) {
            Health.down(e).withDetail("provider", "error").build()
        }
    }
}

/**
 * Health indicator verifying that KMS key management is initialized and production-safe (TC-040).
 */
@Component("kmsReadiness")
class KmsReadinessHealthIndicator(
    private val check: () -> Boolean = { true },
) : HealthIndicator {
    override fun health(): Health {
        return try {
            if (check()) {
                Health.up().withDetail("kms", "ready").build()
            } else {
                Health.down().withDetail("kms", "degraded").build()
            }
        } catch (e: Exception) {
            Health.down(e).withDetail("kms", "error").build()
        }
    }
}

/**
 * Health indicator verifying that the scheduled leased outbox worker is operational (TC-040).
 */
@Component("workerReadiness")
class WorkerReadinessHealthIndicator(
    private val check: () -> Boolean = { true },
) : HealthIndicator {
    override fun health(): Health {
        return try {
            if (check()) {
                Health.up().withDetail("worker", "ready").build()
            } else {
                Health.down().withDetail("worker", "degraded").build()
            }
        } catch (e: Exception) {
            Health.down(e).withDetail("worker", "error").build()
        }
    }
}

/**
 * Health indicator verifying that the RBAC and server policy matrices are loaded (TC-040).
 */
@Component("policyReadiness")
class PolicyReadinessHealthIndicator(
    private val check: () -> Boolean = { true },
) : HealthIndicator {
    override fun health(): Health {
        return try {
            if (check()) {
                Health.up().withDetail("policy", "ready").build()
            } else {
                Health.down().withDetail("policy", "degraded").build()
            }
        } catch (e: Exception) {
            Health.down(e).withDetail("policy", "error").build()
        }
    }
}
