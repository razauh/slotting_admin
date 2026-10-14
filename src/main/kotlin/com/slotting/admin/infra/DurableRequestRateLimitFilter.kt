package com.slotting.admin.infra

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.DurableAuthService
import com.slotting.admin.auth.PrincipalKind
import jakarta.servlet.FilterChain
import jakarta.servlet.ReadListener
import jakarta.servlet.ServletInputStream
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletRequestWrapper
import jakarta.servlet.http.HttpServletResponse
import org.springframework.core.annotation.Order
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.filter.OncePerRequestFilter
import java.nio.charset.StandardCharsets
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.io.SequenceInputStream
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

data class DurableRateLimitDecision(
    val allowed: Boolean,
    val bucket: String,
    val retryAfterSeconds: Long,
    val quarantined: Boolean,
    val limit: Int = 0,
    val remainingRequests: Int = 0,
)

interface DurableRequestRateLimitPolicy {
    fun evaluate(tenantId: String, actorId: String?, deviceId: String?, clientIp: String, category: String): DurableRateLimitDecision
    fun clearQuarantine(tenantId: String, actorId: String, reviewerId: String, reason: String): Boolean
}

@Service
class DurableRequestRateLimitService(
    private val jdbc: JdbcTemplate,
    private val clock: Clock = Clock.systemUTC(),
    private val pepper: String = System.getenv("SLOTTING_PASSWORD_PEPPER").orEmpty(),
) : DurableRequestRateLimitPolicy {
    private val cleanupSequence = AtomicLong()

    @Transactional
    override fun evaluate(tenantId: String, actorId: String?, deviceId: String?, clientIp: String, category: String): DurableRateLimitDecision {
        val now = Instant.now(clock)
        if (cleanupSequence.incrementAndGet() % 1024L == 0L) {
            jdbc.update("delete from request_rate_bucket where window_start < ?", Timestamp.from(now.minusSeconds(86_400)))
        }
        val window = now.epochSecond / 60 * 60
        val windowStart = Timestamp.from(Instant.ofEpochSecond(window))
        val limits = limits(category)
        val bucketSubjects = mutableListOf<Pair<String, String>>()
        if (!actorId.isNullOrBlank()) {
            val actorHash = digest("actor", "$tenantId:$actorId")
            val quarantined = jdbc.queryForObject(
                "select exists(select 1 from request_abuse_quarantine where tenant_id = ? and actor_hash = ?)",
                Boolean::class.java,
                tenantId,
                actorHash,
            ) ?: false
            if (quarantined) return DurableRateLimitDecision(false, "USER_QUARANTINE", 300, true, 0, 0)
            bucketSubjects += "USER" to actorHash
            if (!deviceId.isNullOrBlank()) bucketSubjects += "DEVICE" to digest("device", "$tenantId:$actorId:$deviceId")
        } else {
            bucketSubjects += "IP" to digest("ip", clientIp)
        }
        var throttledBucket: String? = null
        var effectiveLimit = 0
        var remainingRequests = Int.MAX_VALUE
        for ((kind, subjectHash) in bucketSubjects) {
            val limit = if (kind == "DEVICE") limits.device else limits.actor
            val count = jdbc.queryForObject(
                "insert into request_rate_bucket (tenant_id, subject_kind, subject_hash, category, window_start, request_count, updated_at) values (?, ?, ?, ?, ?, 1, ?) on conflict (tenant_id, subject_kind, subject_hash, category, window_start) do update set request_count = request_rate_bucket.request_count + 1, updated_at = excluded.updated_at returning request_count",
                Int::class.java,
                tenantId,
                kind,
                subjectHash,
                category,
                windowStart,
                Timestamp.from(now),
            ) ?: 0
            if (effectiveLimit == 0 || limit - count < remainingRequests) {
                effectiveLimit = limit
                remainingRequests = (limit - count).coerceAtLeast(0)
            }
            if (count > limit && throttledBucket == null) throttledBucket = kind
            if (kind == "USER" && count > limit + 10) {
                val created = jdbc.update(
                    "insert into request_abuse_quarantine (tenant_id, actor_hash, reason, created_at) values (?, ?, 'SUSTAINED_RATE_LIMIT_ABUSE', ?) on conflict (tenant_id, actor_hash) do nothing",
                    tenantId,
                    subjectHash,
                    Timestamp.from(now),
                )
                if (created == 1) {
                    jdbc.update(
                        "insert into request_abuse_quarantine_audit (tenant_id, actor_hash, action, reviewer_id, reason, occurred_at) values (?, ?, 'PLACED', 'system', 'SUSTAINED_RATE_LIMIT_ABUSE', ?)",
                        tenantId,
                        subjectHash,
                        Timestamp.from(now),
                    )
                }
            }
        }
        val bucket = throttledBucket
        return DurableRateLimitDecision(
            bucket == null,
            bucket ?: "ALLOWED",
            if (bucket == null) 0 else 60 - now.epochSecond % 60,
            false,
            effectiveLimit,
            remainingRequests,
        )
    }

    @Transactional
    override fun clearQuarantine(tenantId: String, actorId: String, reviewerId: String, reason: String): Boolean {
        require(reason.isNotBlank() && reason.length <= 500)
        val actorHash = digest("actor", "$tenantId:$actorId")
        val removed = jdbc.update("delete from request_abuse_quarantine where tenant_id = ? and actor_hash = ?", tenantId, actorHash)
        if (removed == 1) {
            jdbc.update(
                "insert into request_abuse_quarantine_audit (tenant_id, actor_hash, action, reviewer_id, reason, occurred_at) values (?, ?, 'CLEARED', ?, ?, ?)",
                tenantId,
                actorHash,
                reviewerId,
                reason.trim(),
                Timestamp.from(Instant.now(clock)),
            )
        }
        return removed == 1
    }

    private fun limits(category: String): Limits = when (category) {
        "AUTH" -> Limits(actor = 20, device = 15)
        "CASHIER" -> Limits(actor = 30, device = 20)
        "GAMEPLAY" -> Limits(actor = 120, device = 90)
        else -> Limits(actor = 60, device = 45)
    }

    private fun digest(kind: String, value: String): String {
        check(pepper.isNotBlank())
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(pepper.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        return mac.doFinal("$kind:$value".toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private data class Limits(val actor: Int, val device: Int)
}

@Component
@Order(0)
class DurableRequestRateLimitFilter(
    private val rateLimits: DurableRequestRateLimitPolicy,
    private val authService: DurableAuthService,
) : OncePerRequestFilter() {
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        val path = request.requestURI
        if (path == "/actuator/health" || path == "/error") {
            filterChain.doFilter(request, response)
            return
        }
        val bearerToken = request.getHeader("Authorization")
            ?.takeIf { it.startsWith("Bearer ", true) }
            ?.substringAfter(' ')
            ?.trim()
        val principal = (bearerToken ?: request.getHeader("X-Session-Token")?.trim())
            ?.let { runCatching { authService.validateAccessToken(it) }.getOrNull() }
        val tenantId = principal?.tenantId ?: "anonymous"
        val category = when {
            path.startsWith("/oauth") || path.startsWith("/auth") || path.endsWith("/devices/verify") -> "AUTH"
            path.contains("withdrawal") || path.contains("deposit") || path.contains("payout") || path.contains("cashier") -> "CASHIER"
            path.contains("/bet") || path.contains("/wager") -> "GAMEPLAY"
            else -> "GENERAL"
        }
        val replay = try {
            inspectableRequest(request)
        } catch (_: PayloadExceedsInspectionLimitException) {
            response.status = 413
            response.contentType = "application/json"
            response.writer.write("{\"error\":\"REQUEST_BODY_TOO_LARGE_FOR_INSPECTION\"}")
            return
        }
        val actorId = principal?.takeIf { it.kind == PrincipalKind.PLAYER }?.id
            ?: if (category == "AUTH") {
                request.getParameter("identifier")
                    ?: Regex("\"(?:username|email|identifier)\"\\s*:\\s*\"([^\"\\r\\n]{3,255})\"", RegexOption.IGNORE_CASE)
                        .find(replay.second)?.groupValues?.get(1)
                    ?: Regex("(?:^|&)(?:username|email|identifier)=([^&]{3,768})", RegexOption.IGNORE_CASE)
                        .find(replay.second)?.groupValues?.get(1)
                        ?.let { runCatching { java.net.URLDecoder.decode(it, StandardCharsets.UTF_8) }.getOrDefault(it) }
            } else null
        val normalizedActorId = actorId?.trim()?.lowercase()?.takeIf { it.length in 3..255 }
        try {
            val decision = rateLimits.evaluate(
                tenantId = tenantId,
                actorId = normalizedActorId,
                deviceId = request.getHeader("X-Device-Id")?.takeIf { it.length in 1..256 },
                clientIp = request.remoteAddr.orEmpty(),
                category = category,
            )
            response.setHeader("RateLimit-Limit", decision.limit.toString())
            response.setHeader("RateLimit-Remaining", decision.remainingRequests.toString())
            if (!decision.allowed) {
                response.status = 429
                response.setHeader("Retry-After", decision.retryAfterSeconds.toString())
                response.contentType = "application/json"
                response.writer.write("{\"error\":\"RATE_LIMITED\",\"bucket\":\"${decision.bucket}\",\"quarantined\":${decision.quarantined}}")
                return
            }
            val requestText = buildString {
                append(request.requestURI)
                append(' ')
                append(request.queryString.orEmpty())
                val names = request.headerNames
                while (names.hasMoreElements()) {
                    val name = names.nextElement()
                    append(' ')
                    append(name)
                    append(':')
                    append(request.getHeader(name).orEmpty())
                }
                append(' ')
                append(replay.second)
            }
            val inspection = WafPayloadSignatures.inspect(requestText, "")
            if (!inspection.isAllowed) {
                response.status = HttpServletResponse.SC_FORBIDDEN
                response.contentType = "application/json"
                response.writer.write("{\"error\":\"MALICIOUS_PAYLOAD\",\"rule\":\"${inspection.matchedRuleId}\"}")
                return
            }
        } catch (_: Exception) {
            response.status = HttpServletResponse.SC_SERVICE_UNAVAILABLE
            response.setHeader("Retry-After", "30")
            response.contentType = "application/json"
            response.writer.write("{\"error\":\"RATE_LIMIT_STORE_UNAVAILABLE\"}")
            return
        }
        filterChain.doFilter(replay.first, response)
    }

    private fun inspectableRequest(request: HttpServletRequest): Pair<HttpServletRequest, String> {
        val contentType = request.contentType?.lowercase().orEmpty()
        if (!contentType.startsWith("application/json") &&
            !contentType.startsWith("application/x-www-form-urlencoded") &&
            !contentType.startsWith("text/") &&
            !contentType.startsWith("application/xml")
        ) return request to ""
        val input = request.inputStream
        val prefix = input.readNBytes(65_537)
        if (prefix.size > 65_536) throw PayloadExceedsInspectionLimitException()
        val charset = runCatching { java.nio.charset.Charset.forName(request.characterEncoding ?: "UTF-8") }.getOrDefault(StandardCharsets.UTF_8)
        val replayStream = SequenceInputStream(ByteArrayInputStream(prefix), input)
        val wrapped = object : HttpServletRequestWrapper(request) {
            override fun getInputStream(): ServletInputStream = object : ServletInputStream() {
                override fun read(): Int = replayStream.read()
                override fun isFinished(): Boolean = replayStream.available() == 0
                override fun isReady(): Boolean = true
                override fun setReadListener(readListener: ReadListener?) = Unit
            }

            override fun getReader(): BufferedReader = BufferedReader(InputStreamReader(inputStream, charset))
        }
        return wrapped to String(prefix, charset)
    }

    private class PayloadExceedsInspectionLimitException : RuntimeException()
}

@org.springframework.web.bind.annotation.RestController
class RequestAbuseQuarantineController(
    private val rateLimits: DurableRequestRateLimitPolicy,
) {
    @org.springframework.web.bind.annotation.PostMapping("/admin/rate-limit/quarantine/{actorId}/clear")
    fun clear(
        @org.springframework.web.bind.annotation.PathVariable actorId: String,
        @org.springframework.web.bind.annotation.RequestParam reason: String,
        @org.springframework.web.bind.annotation.RequestAttribute(name = "authenticatedPrincipal", required = false) principal: com.slotting.admin.auth.AuthenticatedPrincipal?,
    ): org.springframework.http.ResponseEntity<Any> {
        if (principal?.kind != PrincipalKind.ADMIN ||
            (AdminRole.SECURITY !in principal.roles && AdminRole.SUPER_ADMIN !in principal.roles)
        ) return org.springframework.http.ResponseEntity.status(403).body(mapOf("error" to "forbidden"))
        if (reason.isBlank() || reason.length > 500) return org.springframework.http.ResponseEntity.badRequest().body(mapOf("error" to "invalid_reason"))
        val cleared = rateLimits.clearQuarantine(principal.tenantId, actorId, principal.id, reason)
        return if (cleared) org.springframework.http.ResponseEntity.ok(mapOf("status" to "CLEARED"))
        else org.springframework.http.ResponseEntity.notFound().build()
    }
}
