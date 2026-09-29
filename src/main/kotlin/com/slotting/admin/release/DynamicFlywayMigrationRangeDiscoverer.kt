package com.slotting.admin.release

import java.io.File

data class MigrationRange(
    val minVersion: Int,
    val maxVersion: Int,
    val expectedVersions: List<Int>,
    val sqlFilesCount: Int,
    val hasGaps: Boolean,
)

/**
 * Dynamically discovers the repository's current Flyway migration ceiling and ensures
 * a contiguous, gap-free chain without permanently hardcoding V37 (TC-041).
 */
class DynamicFlywayMigrationRangeDiscoverer {

    private val migrationPattern = Regex("^V(\\d+)__.*\\.sql$")

    fun discoverRange(migrationDirectory: File): MigrationRange {
        require(migrationDirectory.exists() && migrationDirectory.isDirectory) {
            "Migration directory ${migrationDirectory.path} does not exist or is not a directory"
        }

        val sqlFiles = migrationDirectory.listFiles { file ->
            file.isFile && migrationPattern.matches(file.name)
        } ?: emptyArray()

        if (sqlFiles.isEmpty()) {
            return MigrationRange(0, 0, emptyList(), 0, false)
        }

        val versions = sqlFiles.mapNotNull { file ->
            migrationPattern.matchEntire(file.name)?.groupValues?.get(1)?.toIntOrNull()
        }.sorted()

        val minVersion = versions.first()
        val maxVersion = versions.last()
        val expected = (minVersion..maxVersion).toList()
        val hasGaps = versions != expected

        return MigrationRange(
            minVersion = minVersion,
            maxVersion = maxVersion,
            expectedVersions = expected,
            sqlFilesCount = sqlFiles.size,
            hasGaps = hasGaps,
        )
    }
}
