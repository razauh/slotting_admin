package com.slotting.admin.withdrawal

import com.slotting.admin.auth.DurableAuthService
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.beans.factory.annotation.Value
import org.springframework.core.annotation.Order
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Service
import org.springframework.stereotype.Component
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestAttribute
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import org.springframework.transaction.annotation.Transactional
import java.nio.charset.StandardCharsets
import java.sql.Timestamp
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.atan2
import kotlin.math.cos
import kotlin.math.sin
import kotlin.math.sqrt

object DeviceTravelVelocityPolicy {
    fun requiresStepUp(
        previousLatitude: Double,
        previousLongitude: Double,
        previousAt: Instant,
        latitude: Double,
        longitude: Double,
        observedAt: Instant,
        maxSpeedKmh: Double,
    ): Boolean {
        val elapsedHours = Duration.between(previousAt, observedAt).toMillis() / 3_600_000.0
        val distance = distanceKm(previousLatitude, previousLongitude, latitude, longitude)
        val speed = if (elapsedHours <= 0.0) if (distance > 0.0) Double.POSITIVE_INFINITY else 0.0 else distance / elapsedHours
        return speed > maxSpeedKmh
    }

    private fun distanceKm(lat1: Double, lon1: Double, lat2: Double, lon2: Double): Double {
        val radius = 6371.0
        val dLat = Math.toRadians(lat2 - lat1)
        val dLon = Math.toRadians(lon2 - lon1)
        val a = sin(dLat / 2) * sin(dLat / 2) + cos(Math.toRadians(lat1)) * cos(Math.toRadians(lat2)) * sin(dLon / 2) * sin(dLon / 2)
        return radius * 2 * atan2(sqrt(a), sqrt(1 - a))
    }
}

data class DeviceTrustDecision(
    val allowed: Boolean,
    val reason: String,
    val deviceId: String,
    val evictedUnverifiedDevice: Boolean = false,
)

interface FinancialDeviceTrustPolicy {
    fun authorize(tenantId: String, playerId: UUID, deviceId: String?, clientIp: String, latitude: Double?, longitude: Double?): DeviceTrustDecision
    fun verify(tenantId: String, playerId: UUID, deviceId: String, password: String, clientIp: String): DeviceTrustDecision
}

@Service
class PlayerFinancialDeviceTrustService(
    private val jdbc: JdbcTemplate,
    private val authService: DurableAuthService,
    private val clock: Clock = Clock.systemUTC(),
    @Value("\${slotting.security.device-cap:5}") private val deviceCap: Int = 5,
    @Value("\${slotting.security.max-travel-speed-kmh:900}") private val maxTravelSpeedKmh: Double = 900.0,
    @Value("\${slotting.security.trusted-location-proxies:}") trustedProxyConfig: String = "",
    private val pepper: String = System.getenv("SLOTTING_PASSWORD_PEPPER").orEmpty(),
) : FinancialDeviceTrustPolicy {
    private val trustedProxies = trustedProxyConfig.split(',').map(String::trim).filter(String::isNotEmpty).toSet()

    @Transactional
    override fun authorize(
        tenantId: String,
        playerId: UUID,
        deviceId: String?,
        clientIp: String,
        latitude: Double?,
        longitude: Double?,
    ): DeviceTrustDecision {
        val normalizedDevice = deviceId?.trim()?.takeIf { it.length in 16..256 }
            ?: return DeviceTrustDecision(false, "DEVICE_STEP_UP_REQUIRED", "")
        jdbc.query("select pg_advisory_xact_lock(hashtextextended(?, 0))", { rs, _ -> rs.getObject(1) }, "$tenantId:$playerId")
        val deviceHash = digest("device", "$tenantId:$playerId:$normalizedDevice")
        val clusterHash = digest("device-cluster", "$tenantId:$normalizedDevice")
        jdbc.query("select pg_advisory_xact_lock(hashtextextended(?, 0))", { rs, _ -> rs.getObject(1) }, clusterHash)
        val reusedByAnotherPlayer = jdbc.queryForObject(
            "select exists(select 1 from trusted_player_device where tenant_id = ? and player_id <> ? and device_cluster_hash = ?)",
            Boolean::class.java,
            tenantId,
            playerId,
            clusterHash,
        ) ?: false
        if (reusedByAnotherPlayer) {
            val now = Timestamp.from(Instant.now(clock))
            jdbc.update(
                "update trusted_player_device set trust_state = 'PENDING_REVIEW' where tenant_id = ? and device_cluster_hash = ? and trust_state in ('PENDING', 'VERIFIED')",
                tenantId,
                clusterHash,
            )
            jdbc.update(
                "insert into trusted_player_device (tenant_id, player_id, device_hash, device_cluster_hash, trust_state, created_at, last_seen_at) values (?, ?, ?, ?, 'PENDING_REVIEW', ?, ?) on conflict (tenant_id, player_id, device_hash) do update set trust_state = 'PENDING_REVIEW', last_seen_at = excluded.last_seen_at",
                tenantId,
                playerId,
                deviceHash,
                clusterHash,
                now,
                now,
            )
            jdbc.update(
                "insert into trusted_player_device_audit (tenant_id, player_id, device_hash, event_type, reason, occurred_at) select tenant_id, player_id, device_hash, 'DEVICE_REVIEW_REQUIRED', 'DEVICE_REUSED_ACROSS_PLAYERS', ? from trusted_player_device where tenant_id = ? and device_cluster_hash = ?",
                now,
                tenantId,
                clusterHash,
            )
            return DeviceTrustDecision(false, "DEVICE_REVIEW_REQUIRED", normalizedDevice)
        }
        val verified = jdbc.queryForObject(
            "select exists(select 1 from trusted_player_device where tenant_id = ? and player_id = ? and device_hash = ? and trust_state = 'VERIFIED')",
            Boolean::class.java,
            tenantId,
            playerId,
            deviceHash,
        ) ?: false
        if (!verified) {
            val now = Timestamp.from(Instant.now(clock))
            jdbc.update(
                "insert into trusted_player_device (tenant_id, player_id, device_hash, device_cluster_hash, trust_state, created_at, last_seen_at) values (?, ?, ?, ?, 'PENDING', ?, ?) on conflict (tenant_id, player_id, device_hash) do update set last_seen_at = excluded.last_seen_at",
                tenantId,
                playerId,
                deviceHash,
                clusterHash,
                now,
                now,
            )
            audit(tenantId, playerId, deviceHash, "DEVICE_STEP_UP_REQUIRED", "DEVICE_UNVERIFIED", now)
            return DeviceTrustDecision(false, "DEVICE_STEP_UP_REQUIRED", normalizedDevice)
        }
        val point = trustedLocation(clientIp, latitude, longitude)
        if (point != null) {
            val previous = jdbc.query(
                "select latitude, longitude, observed_at from player_device_travel_event where tenant_id = ? and player_id = ? order by observed_at desc limit 1",
                { rs, _ -> Triple(rs.getDouble("latitude"), rs.getDouble("longitude"), rs.getTimestamp("observed_at").toInstant()) },
                tenantId,
                playerId,
            ).firstOrNull()
            if (previous != null) {
                if (DeviceTravelVelocityPolicy.requiresStepUp(
                        previous.first,
                        previous.second,
                        previous.third,
                        point.first,
                        point.second,
                        Instant.now(clock),
                        maxTravelSpeedKmh,
                    )
                ) {
                    audit(tenantId, playerId, deviceHash, "DEVICE_STEP_UP_REQUIRED", "IMPOSSIBLE_TRAVEL", Timestamp.from(Instant.now(clock)))
                    return DeviceTrustDecision(false, "DEVICE_STEP_UP_REQUIRED", normalizedDevice)
                }
            }
            jdbc.update(
                "insert into player_device_travel_event (tenant_id, player_id, device_hash, ip_hash, latitude, longitude, observed_at) values (?, ?, ?, ?, ?, ?, ?)",
                tenantId,
                playerId,
                deviceHash,
                digest("ip", "$tenantId:$clientIp"),
                point.first,
                point.second,
                Timestamp.from(Instant.now(clock)),
            )
        }
        jdbc.update("update trusted_player_device set last_seen_at = ? where tenant_id = ? and player_id = ? and device_hash = ?", Timestamp.from(Instant.now(clock)), tenantId, playerId, deviceHash)
        return DeviceTrustDecision(true, "DEVICE_VERIFIED", normalizedDevice)
    }

    @Transactional
    override fun verify(tenantId: String, playerId: UUID, deviceId: String, password: String, clientIp: String): DeviceTrustDecision {
        val normalizedDevice = deviceId.trim().takeIf { it.length in 16..256 }
            ?: return DeviceTrustDecision(false, "INVALID_DEVICE", deviceId)
        val credential = authService.findCredentialByPlayerId(tenantId, playerId)
            ?: return DeviceTrustDecision(false, "STEP_UP_FAILED", normalizedDevice)
        if (authService.authenticatePlayer(tenantId, credential.identifier, password) == null) {
            return DeviceTrustDecision(false, "STEP_UP_FAILED", normalizedDevice)
        }
        jdbc.query("select pg_advisory_xact_lock(hashtextextended(?, 0))", { rs, _ -> rs.getObject(1) }, "$tenantId:$playerId")
        val deviceHash = digest("device", "$tenantId:$playerId:$normalizedDevice")
        val clusterHash = digest("device-cluster", "$tenantId:$normalizedDevice")
        jdbc.query("select pg_advisory_xact_lock(hashtextextended(?, 0))", { rs, _ -> rs.getObject(1) }, clusterHash)
        val reusedByAnotherPlayer = jdbc.queryForObject(
            "select exists(select 1 from trusted_player_device where tenant_id = ? and player_id <> ? and device_cluster_hash = ?)",
            Boolean::class.java,
            tenantId,
            playerId,
            clusterHash,
        ) ?: false
        if (reusedByAnotherPlayer) return DeviceTrustDecision(false, "DEVICE_REVIEW_REQUIRED", normalizedDevice)
        val current = jdbc.queryForObject(
            "select exists(select 1 from trusted_player_device where tenant_id = ? and player_id = ? and device_hash = ? and trust_state = 'VERIFIED')",
            Boolean::class.java,
            tenantId,
            playerId,
            deviceHash,
        ) ?: false
        if (current) return DeviceTrustDecision(true, "DEVICE_ALREADY_VERIFIED", normalizedDevice)
        val verifiedCount = jdbc.queryForObject(
            "select count(*) from trusted_player_device where tenant_id = ? and player_id = ? and trust_state = 'VERIFIED'",
            Long::class.java,
            tenantId,
            playerId,
        )?.toInt() ?: 0
        var evicted = false
        if (verifiedCount >= deviceCap) {
            val oldestPending = jdbc.query(
                "select device_hash from trusted_player_device where tenant_id = ? and player_id = ? and trust_state = 'PENDING' order by created_at limit 1 for update",
                { rs, _ -> rs.getString("device_hash") },
                tenantId,
                playerId,
            ).firstOrNull()
            if (oldestPending == null) return DeviceTrustDecision(false, "DEVICE_CAP_EXCEEDED", normalizedDevice)
            jdbc.update(
                "update trusted_player_device set trust_state = 'DENIED', revoked_at = ? where tenant_id = ? and player_id = ? and device_hash = ? and trust_state = 'PENDING'",
                Timestamp.from(Instant.now(clock)),
                tenantId,
                playerId,
                oldestPending,
            )
            audit(tenantId, playerId, oldestPending, "DEVICE_ENROLLMENT_DENIED", "DEVICE_CAP_EXCEEDED", Timestamp.from(Instant.now(clock)))
            return DeviceTrustDecision(false, "DEVICE_CAP_EXCEEDED", normalizedDevice, true)
        }
        val now = Timestamp.from(Instant.now(clock))
        jdbc.update(
            "insert into trusted_player_device (tenant_id, player_id, device_hash, device_cluster_hash, trust_state, created_at, verified_at, last_seen_at) values (?, ?, ?, ?, 'VERIFIED', ?, ?, ?) on conflict (tenant_id, player_id, device_hash) do update set trust_state = 'VERIFIED', verified_at = excluded.verified_at, last_seen_at = excluded.last_seen_at, revoked_at = null",
            tenantId,
            playerId,
            deviceHash,
            clusterHash,
            now,
            now,
            now,
        )
        audit(tenantId, playerId, deviceHash, "DEVICE_TRUST_GRANTED", "PASSWORD_REAUTHENTICATED", now)
        return DeviceTrustDecision(true, "DEVICE_VERIFIED", normalizedDevice, evicted)
    }

    private fun trustedLocation(clientIp: String, latitude: Double?, longitude: Double?): Pair<Double, Double>? {
        if (clientIp !in trustedProxies || latitude == null || longitude == null) return null
        if (!latitude.isFinite() || !longitude.isFinite() || latitude !in -90.0..90.0 || longitude !in -180.0..180.0) return null
        return latitude to longitude
    }

    private fun audit(tenantId: String, playerId: UUID, deviceHash: String, event: String, reason: String, occurredAt: Timestamp) {
        jdbc.update(
            "insert into trusted_player_device_audit (tenant_id, player_id, device_hash, event_type, reason, occurred_at) values (?, ?, ?, ?, ?, ?)",
            tenantId,
            playerId,
            deviceHash,
            event,
            reason,
            occurredAt,
        )
    }

    private fun digest(kind: String, value: String): String {
        check(pepper.isNotBlank())
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(pepper.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        return mac.doFinal("$kind:$value".toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

}

data class VerifyFinancialDeviceRequest(val deviceId: String, val password: String)

@RestController
class PlayerFinancialDeviceTrustController(
    private val deviceTrustPolicy: FinancialDeviceTrustPolicy,
) {
    @PostMapping("/api/v1/tenants/{tenantId}/devices/verify")
    fun verify(
        @PathVariable tenantId: String,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
        @RequestBody request: VerifyFinancialDeviceRequest,
        servletRequest: HttpServletRequest,
    ): ResponseEntity<Any> {
        if (principal == null || principal.kind != PrincipalKind.PLAYER) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "UNAUTHENTICATED"))
        }
        if (principal.tenantId != tenantId) return ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "FORBIDDEN"))
        val playerId = runCatching { UUID.fromString(principal.id) }.getOrNull()
            ?: return ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "FORBIDDEN"))
        val decision = deviceTrustPolicy.verify(tenantId, playerId, request.deviceId, request.password, servletRequest.remoteAddr.orEmpty())
        if (decision.allowed) {
            return ResponseEntity.ok(
                mapOf(
                    "status" to "DEVICE_VERIFIED",
                    "deviceId" to decision.deviceId,
                    "evictedUnverifiedDevice" to decision.evictedUnverifiedDevice,
                    "notice" to if (decision.evictedUnverifiedDevice) "An older unverified device was denied because the device cap was reached." else null,
                )
            )
        }
        if (decision.evictedUnverifiedDevice) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(
                mapOf(
                    "error" to decision.reason,
                    "evictedUnverifiedDevice" to true,
                    "notice" to "An older unverified device was denied because the device cap was reached.",
                )
            )
        }
        val status = when (decision.reason) {
            "STEP_UP_FAILED" -> HttpStatus.UNAUTHORIZED
            "DEVICE_CAP_EXCEEDED" -> HttpStatus.CONFLICT
            else -> HttpStatus.PRECONDITION_REQUIRED
        }
        return ResponseEntity.status(status).body(mapOf("error" to decision.reason, "deviceId" to decision.deviceId))
    }
}

@Component
@Order(2)
class PlayerFinancialDeviceTrustFilter(
    private val deviceTrustPolicy: FinancialDeviceTrustPolicy,
) : org.springframework.web.filter.OncePerRequestFilter() {
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: jakarta.servlet.http.HttpServletResponse,
        filterChain: jakarta.servlet.FilterChain,
    ) {
        val path = request.requestURI.lowercase()
        val method = request.method.uppercase()
        val isMutation = method in setOf("POST", "PUT", "PATCH", "DELETE")
        val protectedOperation = isMutation && (
            path.contains("deposit") ||
                path.contains("wallet") ||
                path.contains("cashier") ||
                path.contains("/bet") ||
                path.contains("/wager") ||
                path.endsWith("/command")
            ) && !path.endsWith("/devices/verify")
        if (!protectedOperation) {
            filterChain.doFilter(request, response)
            return
        }
        val principal = request.getAttribute("authenticatedPrincipal") as? AuthenticatedPrincipal
        if (principal?.kind != PrincipalKind.PLAYER) {
            filterChain.doFilter(request, response)
            return
        }
        val tenantId = Regex("/tenants/([^/]+)", RegexOption.IGNORE_CASE).find(request.requestURI)?.groupValues?.get(1)
            ?: principal.tenantId
        if (tenantId != principal.tenantId) {
            response.status = HttpStatus.FORBIDDEN.value()
            response.contentType = "application/json"
            response.writer.write("{\"error\":\"FORBIDDEN\"}")
            return
        }
        val playerId = runCatching { UUID.fromString(principal.id) }
            .getOrElse { UUID.nameUUIDFromBytes(principal.id.toByteArray()) }
        val trust = try {
            deviceTrustPolicy.authorize(
                tenantId,
                playerId,
                request.getHeader("X-Device-Id"),
                request.remoteAddr.orEmpty(),
                request.getHeader("X-Geo-Latitude")?.toDoubleOrNull(),
                request.getHeader("X-Geo-Longitude")?.toDoubleOrNull(),
            )
        } catch (_: Exception) {
            response.status = HttpStatus.SERVICE_UNAVAILABLE.value()
            response.contentType = "application/json"
            response.writer.write("{\"error\":\"DEVICE_TRUST_STORE_UNAVAILABLE\"}")
            return
        }
        if (!trust.allowed) {
            response.status = HttpStatus.PRECONDITION_REQUIRED.value()
            response.contentType = "application/json"
            response.writer.write("{\"error\":\"${trust.reason}\",\"signal\":\"DEVICE\"}")
            return
        }
        filterChain.doFilter(request, response)
    }
}
