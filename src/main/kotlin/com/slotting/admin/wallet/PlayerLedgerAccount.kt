package com.slotting.admin.wallet

object PlayerLedgerAccount {
    const val PREFIX = "PLAYER:"

    fun accountReference(ownerReference: String): String =
        if (ownerReference.startsWith(PREFIX)) ownerReference else PREFIX + ownerReference

    fun ownerId(ownerReference: String): String =
        ownerReference.removePrefix(PREFIX)
}
