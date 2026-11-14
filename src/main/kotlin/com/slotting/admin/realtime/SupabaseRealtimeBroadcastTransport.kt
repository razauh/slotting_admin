package com.slotting.admin.realtime

import com.fasterxml.jackson.databind.ObjectMapper
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

sealed interface RealtimeBroadcastFailure {
    data class Unauthorized(val status: Int) : RealtimeBroadcastFailure
    data class Rejected(val status: Int) : RealtimeBroadcastFailure
    data class Unavailable(val detail: String) : RealtimeBroadcastFailure
}

fun interface BroadcastHttpSender {
    fun post(url: String, apikey: String, authorization: String, body: String): Int
}

class HttpBroadcastSender(
    private val client: HttpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build(),
) : BroadcastHttpSender {
    override fun post(url: String, apikey: String, authorization: String, body: String): Int {
        val request = HttpRequest.newBuilder(URI.create(url))
            .timeout(Duration.ofSeconds(5))
            .header("apikey", apikey)
            .header("Authorization", authorization)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()
        return client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode()
    }
}

class SupabaseRealtimeBroadcastTransport(
    private val baseUrl: String,
    private val serviceRoleKey: String,
    private val apikey: String,
    private val sender: BroadcastHttpSender = HttpBroadcastSender(),
    private val maxAttempts: Int = 2,
    private val retryDelayMillis: Long = 50,
    private val mapper: ObjectMapper = ObjectMapper(),
) : RealtimeHintTransport {
    val sent = AtomicLong()
    val failed = AtomicLong()
    val lastFailure = AtomicReference<RealtimeBroadcastFailure?>(null)

    override fun send(channel: String, hints: List<RealtimeHint>) {
        if (hints.isEmpty()) {
            return
        }
        val body = body(channel, hints)
        val url = "${baseUrl.trimEnd('/')}/realtime/v1/api/broadcast"
        lastFailure.set(null)
        repeat(maxAttempts) { attempt ->
            try {
                val status = sender.post(url, apikey, "Bearer $serviceRoleKey", body)
                if (status in 200..299) {
                    sent.incrementAndGet()
                    return
                }
                lastFailure.set(
                    if (status == 401 || status == 403) {
                        RealtimeBroadcastFailure.Unauthorized(status)
                    } else {
                        RealtimeBroadcastFailure.Rejected(status)
                    }
                )
            } catch (error: Exception) {
                lastFailure.set(RealtimeBroadcastFailure.Unavailable("broadcast request failed"))
            }
            if (attempt < maxAttempts - 1) {
                try {
                    Thread.sleep(retryDelayMillis)
                } catch (interrupted: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }
        }
        failed.incrementAndGet()
    }

    private fun body(channel: String, hints: List<RealtimeHint>): String {
        val messages = hints.map { hint ->
            mapOf(
                "topic" to channel,
                "event" to hint.event,
                "private" to true,
                "payload" to (hint.payload + mapOf("eventId" to hint.eventId, "sequence" to hint.sequence)),
            )
        }
        return mapper.writeValueAsString(mapOf("messages" to messages))
    }
}
