package com.slotting.admin.provider.port

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

data class ProviderHttpResponse(
    val statusCode: Int,
    val body: String,
    val headers: Map<String, List<String>>,
)

class ProviderHttpClient(
    private val transport: ((HttpRequest) -> HttpResponse<String>)? = null,
) {
    fun execute(
        config: ProviderConfiguration,
        method: String,
        path: String,
        headers: Map<String, String> = emptyMap(),
        body: String? = null,
    ): ProviderHttpResponse {
        config.validateNetworkSafety()
        require(method.matches(Regex("[A-Z]+")))
        require(path.startsWith("/") && !path.startsWith("//"))
        val baseUri = URI.create(config.baseUrl.trimEnd('/') + "/")
        val uri = baseUri.resolve(path.removePrefix("/"))
        require(uri.scheme == baseUri.scheme && uri.host == baseUri.host && uri.port == baseUri.port)
        val requestBuilder = HttpRequest.newBuilder(uri)
            .timeout(Duration.ofMillis(config.timeoutMs))
            .method(method, body?.let(HttpRequest.BodyPublishers::ofString) ?: HttpRequest.BodyPublishers.noBody())
        headers.forEach { (name, value) -> requestBuilder.header(name, value) }
        val request = requestBuilder.build()
        if (transport != null) {
            val raw = transport.invoke(request)
            return ProviderHttpResponse(raw.statusCode(), raw.body(), raw.headers().map())
        }
        val raw = HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(config.timeoutMs))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build()
            .send(request, HttpResponse.BodyHandlers.ofByteArray())
        if (raw.body().size > 64_000) {
            throw IllegalStateException("Provider response exceeds the safe size bound")
        }
        return ProviderHttpResponse(
            statusCode = raw.statusCode(),
            body = String(raw.body(), Charsets.UTF_8),
            headers = raw.headers().map(),
        )
    }
}
