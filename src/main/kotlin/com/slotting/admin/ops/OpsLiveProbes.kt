package com.slotting.admin.ops

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object OpsWatchBaseline {
    const val JWKS_HASH = "20b1f01af6a89158329fb9d1246ff818143560fad96892fab603adc5c2931dc0"
}

class OpsLiveProbes(
    private val baseUrl: String,
    private val anonKey: String,
    private val jwtSecret: String,
) {
    private val http: HttpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()

    fun mintBridgeToken(): String {
        val header = encode("""{"alg":"HS256","typ":"JWT"}""")
        val expiry = Instant.now().plusSeconds(900).epochSecond
        val payload = encode(
            """{"sub":"00000000-0000-0000-0000-0000000a0b01","tenant_id":"ops-watch","player_id":"00000000-0000-0000-0000-0000000a0b01","session_id":"00000000-0000-0000-0000-0000000a0b02","role":"authenticated","aud":"authenticated","exp":$expiry}""",
        )
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(jwtSecret.toByteArray(), "HmacSHA256"))
        val signature = Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal("$header.$payload".toByteArray()))
        return "$header.$payload.$signature"
    }

    fun edgeStatus(): Int = status("$baseUrl/rest/v1/player_rg_limits?select=limit_id&limit=1", mintBridgeToken())

    fun rootStatus(): Int = status("$baseUrl/rest/v1/", null)

    fun jwksHash(): String? {
        val request = HttpRequest.newBuilder(URI.create("$baseUrl/auth/v1/.well-known/jwks.json"))
            .timeout(Duration.ofSeconds(5))
            .header("apikey", anonKey)
            .GET()
            .build()
        val response = http.send(request, HttpResponse.BodyHandlers.ofByteArray())
        if (response.statusCode() != 200) {
            return null
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(response.body())
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun status(url: String, bearer: String?): Int {
        val builder = HttpRequest.newBuilder(URI.create(url))
            .timeout(Duration.ofSeconds(5))
            .header("apikey", anonKey)
            .GET()
        if (bearer != null) {
            builder.header("Authorization", "Bearer $bearer")
        }
        return http.send(builder.build(), HttpResponse.BodyHandlers.discarding()).statusCode()
    }

    private fun encode(value: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(value.toByteArray())
}
