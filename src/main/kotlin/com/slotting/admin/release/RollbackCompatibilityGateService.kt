package com.slotting.admin.release

enum class RollbackMethod {
    DATABASE_SNAPSHOT_RESTORE_OVERWRITING_LEDGER,
    APPLICATION_BINARY_ROLLBACK_WITH_COMPENSATING_JOURNAL,
}

data class RollbackMethodValidation(
    val isPermitted: Boolean,
    val reason: String,
)

/**
 * Ensures financial ledger transactions are never erased during rollback (TC-041).
 * Forward-only double-entry ledger history is immutable; all corrections must use compensating journal entries.
 */
object FinancialLedgerRollbackProtection {

    fun validateRollbackMethod(method: RollbackMethod): RollbackMethodValidation {
        return when (method) {
            RollbackMethod.DATABASE_SNAPSHOT_RESTORE_OVERWRITING_LEDGER -> RollbackMethodValidation(
                isPermitted = false,
                reason = "Destructive ledger rollbacks prohibited. All financial corrections must proceed via compensating double-entry journal postings.",
            )
            RollbackMethod.APPLICATION_BINARY_ROLLBACK_WITH_COMPENSATING_JOURNAL -> RollbackMethodValidation(
                isPermitted = true,
                reason = "Application binary rollback with forward-only compensating entries permitted.",
            )
        }
    }
}

data class MigrationCompatibilityEvidence(
    val hasDestructiveDrop: Boolean,
    val isBackwardCompatible: Boolean,
    val supportedPreviousBinaryVersion: String,
    val targetRollbackBinaryVersion: String,
)

enum class RollbackDecision {
    ROLLBACK_SAFE,
    ROLLBACK_UNSAFE_FORWARD_FIX_REQUIRED,
}

data class RollbackCompatibilityEvaluation(
    val isRollbackSafe: Boolean,
    val decision: RollbackDecision,
    val reasons: List<String>,
)

/**
 * Evaluates whether an application binary rollback is safe against current schema state (TC-041).
 * Detects destructive or backward-incompatible schema changes and mandates roll-forward fix instead.
 */
class RollbackCompatibilityGateService {

    fun evaluateRollback(evidence: MigrationCompatibilityEvidence): RollbackCompatibilityEvaluation {
        val reasons = mutableListOf<String>()

        if (evidence.hasDestructiveDrop) {
            reasons.add("Schema contains destructive dropped columns/tables; older binary cannot operate safely")
        }
        if (!evidence.isBackwardCompatible) {
            reasons.add("Migration broke backward-compatibility for prior binary versions")
        }
        if (evidence.targetRollbackBinaryVersion < evidence.supportedPreviousBinaryVersion) {
            reasons.add("Target rollback binary version ${evidence.targetRollbackBinaryVersion} is older than supported previous binary version ${evidence.supportedPreviousBinaryVersion}")
        }

        val isSafe = reasons.isEmpty()
        val decision = if (isSafe) RollbackDecision.ROLLBACK_SAFE else RollbackDecision.ROLLBACK_UNSAFE_FORWARD_FIX_REQUIRED

        return RollbackCompatibilityEvaluation(
            isRollbackSafe = isSafe,
            decision = decision,
            reasons = reasons,
        )
    }
}
