package com.slotting.admin.config

import org.flywaydb.core.Flyway
import org.flywaydb.core.api.FlywayException
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.flyway.FlywayMigrationStrategy
import org.springframework.boot.actuate.health.Health
import org.springframework.boot.actuate.health.HealthIndicator
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.context.properties.ConfigurationProperties
import java.util.concurrent.atomic.AtomicReference

data class SchemaMigrationStatus(
    val state: State,
    val version: String?,
    val durationMs: Long?,
    val failure: Failure?,
) {
    enum class State { NOT_STARTED, READY, FAILED }

    data class Failure(val migration: String, val type: String)
}

@ConfigurationProperties("slotting.schema")
data class SchemaMigrationProperties(val supportedVersion: Int = 38)

@Configuration
@EnableConfigurationProperties(SchemaMigrationProperties::class)
class SchemaMigrationConfiguration(
    private val properties: SchemaMigrationProperties,
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val status = AtomicReference(SchemaMigrationStatus(SchemaMigrationStatus.State.NOT_STARTED, null, null, null))

    @Bean
    fun flywayMigrationStrategy(): FlywayMigrationStrategy = FlywayMigrationStrategy { flyway ->
        val startedAt = System.nanoTime()
        try {
            flyway.migrate()
            flyway.validate()
            val version = flyway.info().current()?.version?.version
            val durationMs = (System.nanoTime() - startedAt) / 1_000_000
            if (version?.toIntOrNull() != properties.supportedVersion) {
                throw SchemaMigrationException("Schema version $version is not supported by this binary")
            }
            status.set(SchemaMigrationStatus(SchemaMigrationStatus.State.READY, version, durationMs, null))
            logger.info("schema_migration_succeeded schemaVersion={} durationMs={}", version, durationMs)
        } catch (failure: Throwable) {
            val failedMigration = flyway.info().all()
                .firstOrNull { it.state?.name?.contains("FAILED") == true }
                ?.version?.version
                ?: "unknown"
            val durationMs = (System.nanoTime() - startedAt) / 1_000_000
            status.set(
                SchemaMigrationStatus(
                    SchemaMigrationStatus.State.FAILED,
                    null,
                    durationMs,
                    SchemaMigrationStatus.Failure(failedMigration, failure::class.simpleName ?: "migration_failure"),
                ),
            )
            logger.error(
                "schema_migration_failed migration={} failureType={} durationMs={}",
                failedMigration,
                failure::class.simpleName ?: "migration_failure",
                durationMs,
            )
            throw failure
        }
    }

    @Bean("schemaMigration")
    fun schemaMigrationHealthIndicator(): HealthIndicator = HealthIndicator {
        val current = status.get()
        when (current.state) {
            SchemaMigrationStatus.State.READY -> Health.up()
                .withDetail("schemaVersion", current.version)
                .withDetail("supportedVersion", properties.supportedVersion)
                .withDetail("durationMs", current.durationMs)
                .build()
            SchemaMigrationStatus.State.FAILED -> Health.down()
                .withDetail("schemaVersion", current.version)
                .withDetail("supportedVersion", properties.supportedVersion)
                .withDetail("failureType", current.failure?.type)
                .withDetail("migration", current.failure?.migration)
                .build()
            SchemaMigrationStatus.State.NOT_STARTED -> Health.down()
                .withDetail("reason", "migration_not_started")
                .withDetail("supportedVersion", properties.supportedVersion)
                .build()
        }
    }
}

class SchemaMigrationException(message: String) : FlywayException(message)
