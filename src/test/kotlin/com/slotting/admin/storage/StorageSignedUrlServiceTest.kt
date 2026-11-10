package com.slotting.admin.storage

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class StorageSignedUrlServiceTest {
    private val tenantA = "tc20-tenant-a"
    private val tenantB = "tc20-tenant-b"
    private val playerA = "00000000-0000-0000-0000-0000000020a1"
    private val playerB = "00000000-0000-0000-0000-0000000020b1"

    private class RecordingTransport(private val base: String) : StorageSignTransport {
        val calls = mutableListOf<Triple<String, String, Long>>()

        override fun sign(bucket: String, objectPath: String, expiresInSeconds: Long): String {
            calls.add(Triple(bucket, objectPath, expiresInSeconds))
            return "$base/storage/v1/object/sign/$bucket/$objectPath?token=fixture"
        }
    }

    @Test
    fun `authorized player receives a signed url scoped to its own path`() {
        val transport = RecordingTransport("https://storage.example")
        val service = StorageSignedUrlService(transport)

        val result = service.issue(tenantA, playerA, "player-documents", "$tenantA/$playerA/evidence.pdf", 120)

        assertTrue(result.url.contains("/storage/v1/object/sign/player-documents/$tenantA/$playerA/evidence.pdf"))
        assertEquals(120, result.expiresInSeconds)
        assertEquals(listOf(Triple("player-documents", "$tenantA/$playerA/evidence.pdf", 120L)), transport.calls)
    }

    @Test
    fun `cross tenant object path is refused before any url is issued`() {
        val transport = RecordingTransport("https://storage.example")
        val service = StorageSignedUrlService(transport)

        assertFailsWith<IllegalArgumentException> {
            service.issue(tenantA, playerA, "player-documents", "$tenantB/$playerB/evidence.pdf", 120)
        }
        assertTrue(transport.calls.isEmpty())
    }

    @Test
    fun `cross player object path inside the same tenant is refused`() {
        val transport = RecordingTransport("https://storage.example")
        val service = StorageSignedUrlService(transport)

        assertFailsWith<IllegalArgumentException> {
            service.issue(tenantA, playerA, "player-documents", "$tenantA/$playerB/evidence.pdf", 120)
        }
        assertTrue(transport.calls.isEmpty())
    }

    @Test
    fun `unknown bucket is refused`() {
        val transport = RecordingTransport("https://storage.example")
        val service = StorageSignedUrlService(transport)

        assertFailsWith<IllegalArgumentException> {
            service.issue(tenantA, playerA, "public-assets", "$tenantA/$playerA/evidence.pdf", 120)
        }
        assertTrue(transport.calls.isEmpty())
    }

    @Test
    fun `ttl must stay inside the short lived window`() {
        val transport = RecordingTransport("https://storage.example")
        val service = StorageSignedUrlService(transport)

        assertFailsWith<IllegalArgumentException> { service.issue(tenantA, playerA, "player-documents", "$tenantA/$playerA/evidence.pdf", 0) }
        assertFailsWith<IllegalArgumentException> { service.issue(tenantA, playerA, "player-documents", "$tenantA/$playerA/evidence.pdf", 301) }
        assertEquals(300, service.issue(tenantA, playerA, "player-documents", "$tenantA/$playerA/evidence.pdf", 300).expiresInSeconds)
    }

    @Test
    fun `leading slash in object path is normalized`() {
        val transport = RecordingTransport("https://storage.example")
        val service = StorageSignedUrlService(transport)

        val result = service.issue(tenantA, playerA, "player-documents", "/$tenantA/$playerA/evidence.pdf", 60)

        assertTrue(result.url.endsWith("/$tenantA/$playerA/evidence.pdf?token=fixture"))
        assertEquals("$tenantA/$playerA/evidence.pdf", transport.calls.single().second)
    }
}
