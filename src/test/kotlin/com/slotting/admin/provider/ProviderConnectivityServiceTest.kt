package com.slotting.admin.provider

import com.slotting.admin.provider.port.ProviderEnvironment
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class ProviderConnectivityServiceTest {
    private val clock = Clock.fixed(Instant.parse("2026-10-31T10:00:00Z"), ZoneOffset.UTC)

    private fun request(
        endpoint: String,
        credentialsAvailable: Boolean = true,
        allowLoopbackForTest: Boolean = true,
        environment: ProviderEnvironment = ProviderEnvironment.SANDBOX,
    ) = ProviderProbeRequest(
        tenantId = "tenant-1",
        providerId = "JAZZCASH",
        environment = environment,
        endpointUrl = endpoint,
        configVersion = 3L,
        credentialsAvailable = credentialsAvailable,
        allowLoopbackForTest = allowLoopbackForTest,
    )

    private fun service(path: String? = "/ok") = ProviderConnectivityService(
        clock = clock,
        probePaths = path?.let { mapOf("JAZZCASH" to it) } ?: emptyMap(),
    )

    @Test
    fun `TC-017-R1 missing credentials and undocumented probe make zero network calls`() {
        val calls = AtomicInteger(0)
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/ok") { exchange ->
            calls.incrementAndGet()
            exchange.sendResponseHeaders(200, 0)
            exchange.close()
        }
        server.start()
        try {
            val service = service()
            val endpoint = "http://127.0.0.1:${server.address.port}"
            assertEquals(ProviderProbeStatus.INVALID_CONFIG, service.probe(request(endpoint, credentialsAvailable = false)).status)
            assertEquals(ProviderProbeStatus.NOT_VERIFIED, service(null).probe(request(endpoint)).status)
            assertEquals(0, calls.get())
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun `TC-017-R2 read-only probe maps success unauthorized and timeout without financial calls`() {
        val methods = mutableListOf<String>()
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val executor = Executors.newCachedThreadPool()
        server.executor = executor
        server.createContext("/ok") { exchange ->
            methods.add(exchange.requestMethod)
            exchange.sendResponseHeaders(200, 0)
            exchange.close()
        }
        server.createContext("/auth") { exchange ->
            methods.add(exchange.requestMethod)
            exchange.sendResponseHeaders(401, 0)
            exchange.close()
        }
        server.createContext("/slow") { exchange ->
            methods.add(exchange.requestMethod)
            Thread.sleep(3_000)
            exchange.sendResponseHeaders(200, 0)
            exchange.close()
        }
        server.start()
        try {
            val endpoint = "http://127.0.0.1:${server.address.port}"
            assertEquals(ProviderProbeStatus.READY, service("/ok").probe(request(endpoint)).status)
            assertEquals(ProviderProbeStatus.UNAUTHORIZED, service("/auth").probe(request(endpoint)).status)
            assertEquals(ProviderProbeStatus.UNREACHABLE, service("/slow").probe(request(endpoint)).status)
            assertEquals(listOf("GET", "GET", "GET"), methods)
        } finally {
            server.stop(0)
            executor.shutdownNow()
        }
    }

    @Test
    fun `TC-017-R3 loopback metadata and private targets are blocked in network mode`() {
        val service = service("/ok")
        assertEquals(
            ProviderProbeStatus.INVALID_CONFIG,
            service.probe(request("http://127.0.0.1:8080", allowLoopbackForTest = false)).status,
        )
        assertEquals(
            ProviderProbeStatus.INVALID_CONFIG,
            service.probe(request("http://169.254.169.254/latest", allowLoopbackForTest = false)).status,
        )
        assertEquals(
            ProviderProbeStatus.INVALID_CONFIG,
            service.probe(request("http://192.168.1.10", allowLoopbackForTest = false)).status,
        )
    }
}
