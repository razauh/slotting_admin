package com.slotting.admin.wallet

/**
 * Outcome-specific semantic contract for WALLET-004.
 */
const val WALLET_STATEMENT_CONTRACT = "Snapshot includes as-of/version; statements map postings, never local activity."

/**
 * Gate to enforce WALLET-004: Balance/statement APIs.
 * Protected risk: "ownership leak/inconsistent page"
 * Semantic contract: "Snapshot includes as-of/version; statements map postings, never local activity."
 */
object WalletStatementBinding {
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("ownership leak/inconsistent page")
        }
    }
}
