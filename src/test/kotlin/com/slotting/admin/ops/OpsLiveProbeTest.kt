package com.slotting.admin.ops

import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.slf4j.LoggerFactory
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class OpsLiveProbeTest {
    private val log = LoggerFactory.getLogger(javaClass)

    @Test
    fun `live d1 edge and jwks comparisons run against the real platform`() {
        val base = System.getenv("SUPABASE_URL").orEmpty()
        val anon = System.getenv("SUPABASE_ANON_KEY").orEmpty()
        val secret = System.getenv("SLOTTING_SUPABASE_JWT_SECRET").orEmpty()
        assumeTrue(base.isNotBlank() && anon.isNotBlank() && secret.isNotBlank())

        val probes = OpsLiveProbes(base, anon, secret)
        val edge = probes.edgeStatus()
        val hash = probes.jwksHash()
        val root = probes.rootStatus()
        val changed = hash != OpsWatchBaseline.JWKS_HASH

        log.info("OPS_JWT_EDGE_STATUS={}", edge)
        log.info("JWT_EDGE_HAS_CHANGED={}", changed)
        log.info("OPS_JWKS_HASH={}", hash)
        log.info("OPS_D2_ROOT_STATUS={}", root)

        assertEquals(200, edge)
        assertEquals(OpsWatchBaseline.JWKS_HASH, hash)
        assertTrue(!changed)
        assertTrue(root in setOf(401, 404, 200))
    }
}
