package com.slotting.admin.wallet

/**
 * Outcome-specific semantic contract for WALLET-003.
 */
const val RESERVATIONS_CONTRACT = "Terminal transitions idempotent; expiry is worker command, never silent deletion."

/**
 * Gate to enforce WALLET-003: Reservations.
 * Protected risk: "double reserve/overdraft/race"
 * Semantic contract: "Terminal transitions idempotent; expiry is worker command, never silent deletion."
 */
object WalletReservationBinding {
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("double reserve/overdraft/race")
        }
    }
}
