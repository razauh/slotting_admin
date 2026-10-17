package com.slotting.admin.provider.port

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.util.concurrent.Executors
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails

class ProviderHttpClientTest {
    @Test
    fun `request timeout is enforced and redirects are not followed`() {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val executor = Executors.newSingleThreadExecutor()
        server.executor = executor
        server.createContext("/slow") { exchange ->
            Thread.sleep(300)
            exchange.sendResponseHeaders(200, 0)
            exchange.close()
        }
        server.createContext("/redirect") { exchange ->
            exchange.responseHeaders.add("Location", "/slow")
            exchange.sendResponseHeaders(302, -1)
            exchange.close()
        }
        server.start()
        try {
            val client = ProviderHttpClient()
            val config = ProviderConfiguration(
                providerId = "test-provider",
                environment = ProviderEnvironment.SANDBOX,
                baseUrl = "http://127.0.0.1:${server.address.port}",
                timeoutMs = 50,
                maxRetries = 0,
            )
            assertFails { client.execute(config, "GET", "/slow") }
            assertEquals(302, client.execute(config.copy(timeoutMs = 1_000), "GET", "/redirect").statusCode)
        } finally {
            server.stop(0)
            executor.shutdownNow()
        }
    }

    @Test
    fun `request path cannot escape the configured provider origin`() {
        val client = ProviderHttpClient()
        val config = ProviderConfiguration("test-provider", ProviderEnvironment.SANDBOX, "https://provider.example")
        assertFails { client.execute(config, "GET", "//attacker.example/collect") }
    }
}
