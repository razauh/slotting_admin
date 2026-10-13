package com.slotting.admin.infra

import org.testcontainers.containers.PostgreSQLContainer
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.DriverManagerDataSource
import javax.sql.DataSource

object PostgresIntegrationSupport {
    private val externalUrl = System.getenv("SLOTTING_ADMIN_DATABASE_URL")
        ?: System.getProperty("spring.datasource.url")
    private val externalUser = System.getenv("SLOTTING_ADMIN_DATABASE_USERNAME")
        ?: System.getProperty("spring.datasource.username")
        ?: "ci_runner"
    private val externalPassword = System.getenv("SLOTTING_ADMIN_DATABASE_PASSWORD")
        ?: System.getProperty("spring.datasource.password")
        ?: "ci_test_password_ephemeral"

    private val container: PostgreSQLContainer<Nothing>? by lazy {
        if (!externalUrl.isNullOrBlank()) {
            null
        } else {
            try {
                PostgreSQLContainer<Nothing>("postgres:16-alpine").apply {
                    withDatabaseName("slotting_admin_ci")
                    withUsername("ci_runner")
                    withPassword("ci_test_password_ephemeral")
                    start()
                }
            } catch (e: Exception) {
                throw IllegalStateException(
                    "PostgreSQL container failed to start and no external SLOTTING_ADMIN_DATABASE_URL was provided. " +
                    "Integration tests require an active PostgreSQL 16 database and cannot be skipped.",
                    e
                )
            }
        }
    }

    private val ALLOWED_HOSTS = setOf(
        "localhost",
        "127.0.0.1",
        "::1",
        "postgres",
        "slotting_admin_ci"
    )

    private fun extractHost(jdbcUrl: String): String {
        val clean = jdbcUrl.removePrefix("jdbc:postgresql://")
        val hostPart = clean.substringBefore("/").substringBefore("?")
        return hostPart.substringBefore(":")
    }

    fun configureProperties(registry: DynamicPropertyRegistry) {
        val url = externalUrl ?: container?.jdbcUrl
            ?: throw IllegalStateException("PostgreSQL database is mandatory for integration tests but unavailable.")
        val user = if (!externalUrl.isNullOrBlank()) externalUser else container?.username ?: "ci_runner"
        val password = if (!externalUrl.isNullOrBlank()) externalPassword else container?.password ?: "ci_test_password_ephemeral"

        val host = extractHost(url).lowercase()
        val isAllowed = host in ALLOWED_HOSTS || host.startsWith("127.")
        require(isAllowed && !url.contains("postgres-ha.internal") && !url.contains("internal.slotting.com")) {
            "Safety guard violation: Integration tests are strictly restricted to approved local/CI database hosts. Unapproved host: '$host' in '$url'"
        }

        registry.add("spring.datasource.url") { url }
        registry.add("spring.datasource.username") { user }
        registry.add("spring.datasource.password") { password }
        registry.add("spring.flyway.enabled") { "true" }
        registry.add("spring.datasource.hikari.maximum-pool-size") { "4" }

        try {
            val ds = org.springframework.jdbc.datasource.DriverManagerDataSource(url, user, password)
            val jdbc = org.springframework.jdbc.core.JdbcTemplate(ds)
            jdbc.update("delete from game_bet_settlement")
            jdbc.update("delete from game_accepted_bet")
            jdbc.update("delete from game_command_receipt")
            jdbc.update("delete from game_fairness_reveal")
            jdbc.update("delete from game_fairness_audit")
            jdbc.update("delete from game_fairness_commitment")
            jdbc.update("delete from game_cumulative_player_limit")
            jdbc.update("delete from game_authoritative_round")
            jdbc.update("delete from game_lifecycle_lease")
        } catch (e: Exception) {
        }
    }

    fun createIsolatedSchema(schemaName: String): IsolatedPostgresSchema {
        require(schemaName.matches(Regex("tc04_[a-f0-9]{12}"))) { "Invalid isolated schema name" }
        val url = externalUrl ?: container?.jdbcUrl
            ?: throw IllegalStateException("PostgreSQL database is mandatory for migration tests but unavailable.")
        val user = if (!externalUrl.isNullOrBlank()) externalUser else container?.username ?: "ci_runner"
        val password = if (!externalUrl.isNullOrBlank()) externalPassword else container?.password ?: "ci_test_password_ephemeral"
        val host = extractHost(url).lowercase()
        val isAllowed = host in ALLOWED_HOSTS || host.startsWith("127.")
        require(isAllowed && !url.contains("postgres-ha.internal") && !url.contains("internal.slotting.com")) {
            "Safety guard violation: migration tests are restricted to approved local/CI PostgreSQL hosts."
        }

        val adminDataSource = DriverManagerDataSource(url, user, password)
        JdbcTemplate(adminDataSource).execute("create schema $schemaName")
        val separator = if (url.contains('?')) '&' else '?'
        val schemaDataSource = DriverManagerDataSource("$url${separator}currentSchema=$schemaName", user, password)
        return IsolatedPostgresSchema(schemaName, schemaDataSource, adminDataSource)
    }
}

class IsolatedPostgresSchema internal constructor(
    val schemaName: String,
    val dataSource: DataSource,
    private val adminDataSource: DataSource,
) : AutoCloseable {
    val jdbc = JdbcTemplate(dataSource)

    override fun close() {
        JdbcTemplate(adminDataSource).execute("drop schema if exists $schemaName cascade")
    }
}
