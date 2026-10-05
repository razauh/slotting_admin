package com.slotting.admin.gameprovider

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.UUID

object AviatorCommandKeys {
    fun placeBetKey(
        tenantId: String,
        gameId: String,
        roundId: String,
        ownerId: String,
        handId: String,
    ): String = "bet:$tenantId:$gameId:$roundId:$ownerId:$handId"

    fun settlementKey(betId: UUID): String = "settle:$betId"

    fun ledgerTransactionReference(kind: String, commandKey: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(commandKey.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        return "TX-$kind-${digest.take(40)}"
    }
}
