package com.slotting.admin.infra

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class MigrationInventoryContractTest {
    @Test
    fun `migration directory matches approved filename inventory`() {
        val migrationDirectory = File("src/main/resources/db/migration")
        val actualFiles = migrationDirectory.listFiles()?.filter { it.isFile }?.map { it.name }.orEmpty()
        val filenamePattern = Regex("V([1-9][0-9]*)__[A-Za-z0-9_]+\\.sql")
        val malformedFiles = actualFiles.filterNot { filenamePattern.matches(it) }
        assertTrue(malformedFiles.isEmpty(), "Malformed migration filenames: $malformedFiles")

        val versions = actualFiles.mapNotNull { filenamePattern.matchEntire(it)?.groupValues?.get(1)?.toInt() }
        val duplicateVersions = versions.groupingBy { it }.eachCount().filterValues { it > 1 }.keys
        assertTrue(duplicateVersions.isEmpty(), "Duplicate migration versions: $duplicateVersions")

        val approvedFiles = setOf(
            "V1__admin_mfa.sql",
            "V2__admin_rbac.sql",
            "V3__scoped_player_profile_search.sql",
            "V4__shared_admin_operation_journal.sql",
            "V5__ledger_timeline_read.sql",
            "V6__withdrawal_review_queue.sql",
            "V7__kyc_review_queue.sql",
            "V8__aml_review_queue.sql",
            "V9__rg_review_queue.sql",
            "V10__manual_adjustment.sql",
            "V11__payment_provider_config.sql",
            "V12__game_provider_config.sql",
            "V13__provider_circuit_breaker.sql",
            "V14__reconciliation_report.sql",
            "V15__reconciliation_exception.sql",
            "V16__admin_audit_retention_legal_hold.sql",
            "V17__operational_schemas.sql",
            "V18__durable_delivery_substrate.sql",
            "V19__durable_auth_sessions.sql",
            "V20__dual_control_approvals.sql",
            "V21__persistent_double_entry_ledger.sql",
            "V22__lossless_timeline_and_wallet_projection.sql",
            "V23__payment_method_lifecycle.sql",
            "V24__durable_deposit_workflow.sql",
            "V25__authoritative_withdrawal_workflow.sql",
            "V26__durable_payout_dispatch_and_reconciliation.sql",
            "V27__authoritative_account_support_and_closure.sql",
            "V28__durable_game_wager_and_settlement_authority.sql",
            "V29__outcome_bound_fairness_authority.sql",
            "V30__authoritative_game_snapshot_and_event_checkpoint.sql",
            "V31__distinct_server_restriction_sources_and_policy_matrix.sql",
            "V32__durable_administrative_bans.sql",
            "V33__durable_responsible_gaming_limits_and_exclusions.sql",
            "V34__durable_fraud_risk_event_and_rule_evaluation.sql",
            "V35__durable_fraud_cases_and_dispositions.sql",
            "V36__operation_bound_attestation_challenges.sql",
            "V37__authoritative_analytics_facts_and_projections.sql",
            "V38__secure_password_reset_token.sql",
            "V39__atomic_command_sequence_allocation.sql",
            "V40__deterministic_command_keys_and_early_claim.sql"
        )

        val actualSet = actualFiles.toSet()
        assertEquals(approvedFiles, actualSet, "Migration filename inventory mismatch; missing=${approvedFiles - actualSet}, unexpected=${actualSet - approvedFiles}")
    }
}
