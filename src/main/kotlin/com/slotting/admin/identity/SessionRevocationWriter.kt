package com.slotting.admin.identity

import java.time.Instant
import java.util.UUID

fun interface SessionRevocationWriter {
    fun record(tenantId: String, sessionId: UUID, revokedAt: Instant, reason: String)

    companion object {
        val NoOp = SessionRevocationWriter { _, _, _, _ -> }
    }
}
