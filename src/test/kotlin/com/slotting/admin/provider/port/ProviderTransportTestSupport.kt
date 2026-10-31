package com.slotting.admin.provider.port

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpHeaders
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.Optional

internal class RecordingTransport(
    private val responder: (HttpRequest) -> HttpResponse<String>,
) {
    val requests = mutableListOf<HttpRequest>()

    fun transport(): (HttpRequest) -> HttpResponse<String> = { request ->
        requests.add(request)
        responder(request)
    }
}

internal fun httpResponse(status: Int, body: String): HttpResponse<String> = object : HttpResponse<String> {
    override fun statusCode(): Int = status
    override fun request(): HttpRequest = HttpRequest.newBuilder(URI.create("https://provider.example/")).build()
    override fun previousResponse(): Optional<HttpResponse<String>> = Optional.empty()
    override fun headers(): HttpHeaders = HttpHeaders.of(emptyMap(), { _, _ -> true })
    override fun body(): String = body
    override fun sslSession(): Optional<javax.net.ssl.SSLSession> = Optional.empty()
    override fun uri(): URI = URI.create("https://provider.example/")
    override fun version(): HttpClient.Version = HttpClient.Version.HTTP_1_1
}
