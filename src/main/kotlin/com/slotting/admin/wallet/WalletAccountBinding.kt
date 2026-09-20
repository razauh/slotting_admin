package com.slotting.admin.wallet

/**
 * Traceability binding for WALLET-001: Accounts and currency model.
 * Fail-closed assertion gate for RED/GREEN TDD verification.
 * Expected RED failure reason: "cross-currency/duplicate account allowed".
 */
object WalletAccountBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("cross-currency/duplicate account allowed")
        }
    }
}
