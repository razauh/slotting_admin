package com.slotting.admin.infra

import kotlin.test.Test
import kotlin.test.assertTrue

class DatabaseBootstrapContractTest {
    @Test
    fun `production migration runner is available on the runtime classpath`() {
        val flywayPresent = runCatching {
            Class.forName("org.flywaydb.core.Flyway")
        }.isSuccess

        assertTrue(flywayPresent, "Spring startup must include the Flyway migration runtime")
    }

    @Test
    fun `operational schemas are part of the versioned migration history`() {
        val migration = javaClass.classLoader.getResource("db/migration/V17__operational_schemas.sql")

        assertTrue(migration != null, "Operational schemas must be versioned as V17")
    }
}
