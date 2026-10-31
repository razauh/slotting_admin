package com.slotting.admin.observability

import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class AlphaTc028ContractTest {
    private val clock = Clock.fixed(Instant.parse("2026-10-31T12:00:00Z"), ZoneOffset.UTC)

    @Test
    fun `TC-028-R1 golden Android JSON preserves identifiers and explicit PKR minor units`() {
        val parsed = parse(
            """
            {
              "schemaVersion": 2,
              "eventId": "11111111-1111-1111-1111-111111111111",
              "occurredAtMillis": 1793448000000,
              "eventType": "API_TIMEOUT",
              "severity": "ERROR",
              "sourceApp": "android",
              "component": "crash-data",
              "environment": "connected",
              "requestId": "req-1",
              "correlationId": "corr-1",
              "causationId": "cause-1",
              "roundId": "round-1",
              "betId": "bet-1",
              "paymentId": "pay-1",
              "ledgerId": "ledger-1",
              "amountMinorUnits": 2500,
              "currency": "PKR",
              "message": "timeout",
              "context": {"screen": "crash", "phase": "FLYING", "retryCount": "2"},
              "stackFrames": ["Frame.one", "Frame.two"]
            }
            """.trimIndent()
        )

        assertEquals("11111111-1111-1111-1111-111111111111", parsed.eventId.toString())
        assertEquals("req-1", parsed.requestId)
        assertEquals("round-1", parsed.roundId)
        assertEquals(2500L, parsed.amountMinorUnits)
        assertEquals("PKR", parsed.currency)
        assertEquals("crash", parsed.context["screen"])
        assertEquals(2, parsed.stackFrames.size)
        assertEquals("player-1", parsed.userId)
        assertNull(parsed.adminId)
    }

    @Test
    fun `TC-028-R2 secrets are redacted and oversized context and stack are bounded`() {
        val longMessage = "token=super-secret " + "a".repeat(5_000)
        val context = (1..40).joinToString(",") { "\"screen$it\":\"${"v".repeat(300)}\"" }
        val frames = (1..40).joinToString(",") { "\"frame-$it-${"x".repeat(600)}\"" }
        val parsed = parse(
            """
            {
              "schemaVersion": 2,
              "eventId": "22222222-2222-2222-2222-222222222222",
              "occurredAtMillis": 1793448000000,
              "eventType": "RENDER_ERROR",
              "severity": "WARN",
              "sourceApp": "android",
              "component": "crash-renderer",
              "environment": "connected",
              "correlationId": "corr-2",
              "message": "$longMessage",
              "context": {"screen": "crash", "password": "hunter2", "token": "abc", "otp": "123456", $context},
              "stackFrames": [$frames]
            }
            """.trimIndent()
        )

        assertTrue(parsed.message!!.length <= 2_000)
        assertTrue(!parsed.message.contains("super-secret"))
        assertEquals(1, parsed.context.size)
        assertEquals("crash", parsed.context["screen"])
        assertTrue(parsed.context.values.all { it.length <= 256 })
        assertEquals(32, parsed.stackFrames.size)
        assertTrue(parsed.stackFrames.all { it.length <= 512 })
        assertTrue(parsed.payloadDigest().length == 64)
    }

    @Test
    fun `TC-028-R3 unsupported schema missing correlation money mismatch INR and forged actor are rejected or sanitized`() {
        assertRejected(DiagnosticEnvelopeRejectionCode.UNSUPPORTED_SCHEMA, json(schemaVersion = 3))
        assertRejected(DiagnosticEnvelopeRejectionCode.MISSING_REQUIRED_FIELD, json(correlationId = null))
        assertRejected(
            DiagnosticEnvelopeRejectionCode.AMOUNT_CURRENCY_MISMATCH,
            json(amount = "2500", currency = null),
        )
        assertRejected(DiagnosticEnvelopeRejectionCode.INVALID_CURRENCY, json(amount = "2500", currency = "INR"))
        assertRejected(DiagnosticEnvelopeRejectionCode.CROSS_TENANT, json(tenantId = "tenant-other"))

        val parsed = parse(json(adminId = "forged-admin", actorRole = "SUPER_ADMIN"))
        assertNull(parsed.adminId)
        assertEquals("player-1", parsed.userId)
    }

    private fun parse(raw: String) = DiagnosticEnvelopeParser.parse(
        rawJson = raw,
        serverActorId = "player-1",
        serverTenantId = "tenant-1",
        serverActorIsAdmin = false,
        clock = clock,
    )

    private fun assertRejected(expected: DiagnosticEnvelopeRejectionCode, raw: String) {
        val rejection = assertFailsWith<DiagnosticEnvelopeRejection> { parse(raw) }
        assertEquals(expected, rejection.code)
    }

    private fun json(
        schemaVersion: Int = 2,
        correlationId: String? = "corr-3",
        amount: String? = null,
        currency: String? = "PKR",
        tenantId: String? = "tenant-1",
        adminId: String? = null,
        actorRole: String? = null,
    ): String {
        val money = if (amount == null) "" else """"amountMinorUnits": $amount, ${currency?.let { "\"currency\": \"$it\"," } ?: ""}"""
        return """
            {
              "schemaVersion": $schemaVersion,
              "eventId": "33333333-3333-3333-3333-333333333333",
              "occurredAtMillis": 1793448000000,
              "eventType": "API_TIMEOUT",
              "severity": "ERROR",
              "sourceApp": "android",
              "component": "crash-data",
              "environment": "connected",
              ${correlationId?.let { "\"correlationId\": \"$it\"," } ?: ""}
              ${tenantId?.let { "\"tenantId\": \"$it\"," } ?: ""}
              ${adminId?.let { "\"adminId\": \"$it\"," } ?: ""}
              ${actorRole?.let { "\"actorRole\": \"$it\"," } ?: ""}
              $money
              "message": "failure"
            }
        """.trimIndent()
    }
}
