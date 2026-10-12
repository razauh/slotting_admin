package com.slotting.admin.migration

import org.flywaydb.core.api.FlywayException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.dao.DataAccessException
import kotlin.test.assertFailsWith

class MigrationSafetyContractTest {
    @Test
    fun migrateToCurrentVersionOverSeededDataSucceeds() {
        MigrationSafetyHarness.open().use { harness ->
            harness.migrateTo(MigrationSafetyHarness.LEGACY_MIGRATION_VERSION)
            harness.seedProductionLikeData()
            val before = harness.legacyRowCounts()

            harness.migrateTo()

            harness.assertCurrentVersion(MigrationSafetyHarness.CURRENT_MIGRATION_VERSION)
            assertEquals(before, harness.legacyRowCounts())
            assertEquals(0, harness.roundVersionBackfillViolationCount())
            assertTrue(harness.lifecycleAttemptJournalExists())
            println("migration_verified version=49 rowCounts=$before")
        }
    }

    @Test
    fun forwardFixMigrationPreservesExistingRows() {
        MigrationSafetyHarness.open().use { harness ->
            harness.migrateTo(MigrationSafetyHarness.LEGACY_MIGRATION_VERSION)
            harness.seedProductionLikeData()
            val before = harness.legacyRowCounts()

            harness.migrateTo()

            assertEquals(before, harness.legacyRowCounts())
            assertEquals(0, harness.roundVersionBackfillViolationCount())
        }
    }

    @Test
    fun backfillVerificationQueryPassesForAllLegacyRows() {
        MigrationSafetyHarness.open().use { harness ->
            harness.migrateTo(MigrationSafetyHarness.LEGACY_MIGRATION_VERSION)
            harness.seedProductionLikeData(listOf(1L, 2L, 5L, 11L))

            harness.migrateTo()

            assertEquals(listOf(1L, 2L, 5L, 11L), harness.backfilledRoundVersions())
            assertEquals(0, harness.roundVersionBackfillViolationCount())
        }
    }

    @Test
    fun constraintChecksRejectViolatingRowsAfterMigration() {
        MigrationSafetyHarness.open().use { harness ->
            harness.migrateTo(MigrationSafetyHarness.LEGACY_MIGRATION_VERSION)
            harness.seedProductionLikeData()
            harness.migrateTo()

            assertFailsWith<DataAccessException> {
                harness.jdbc.update(
                    "update game_event_journal set round_version = 0 where sequence_id = 1",
                )
            }
            assertFailsWith<DataAccessException> {
                harness.jdbc.update(
                    "insert into game_event_journal (event_id, tenant_id, game_id, round_id, sequence_id, event_name, payload_json, target_scope, target_owner_id, timestamp_millis, created_at, round_version) " +
                        "select gen_random_uuid(), tenant_id, game_id, round_id, 99, event_name, payload_json, target_scope, target_owner_id, timestamp_millis, created_at, round_version from game_event_journal where sequence_id = 1",
                )
            }
            assertFalse(harness.roundVersionBackfillViolationCount() > 0)
        }
    }

    @Test
    fun invalidLegacyRowsFailMigrationWithoutRecordingVersionSuccess() {
        MigrationSafetyHarness.open().use { harness ->
            harness.migrateTo(MigrationSafetyHarness.LEGACY_MIGRATION_VERSION)
            harness.seedProductionLikeData(roundVersions = emptyList(), malformedRoundVersion = true)

            assertFailsWith<FlywayException> { harness.migrateTo() }

            harness.assertCurrentVersion(MigrationSafetyHarness.LEGACY_MIGRATION_VERSION)
            assertEquals(0, harness.successfulMigrationCount("47"))
        }
    }

    @Test
    fun partialSeedFailureRollsBackAllSeedTables() {
        MigrationSafetyHarness.open().use { harness ->
            harness.migrateTo(MigrationSafetyHarness.LEGACY_MIGRATION_VERSION)

            assertFailsWith<DataAccessException> { harness.seedProductionLikeData(forceFailure = true) }

            assertTrue(harness.legacyRowCounts().values.all { it == 0 })
            harness.assertCurrentVersion(MigrationSafetyHarness.LEGACY_MIGRATION_VERSION)
        }
    }
}
