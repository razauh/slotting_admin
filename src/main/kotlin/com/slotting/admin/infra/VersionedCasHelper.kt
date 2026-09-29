package com.slotting.admin.infra

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure

/**
 * Common versioned-update helper ensuring optimistic updates check affected row counts.
 * Prevents phantom success receipts on concurrent CAS collisions.
 */
object VersionedCasHelper {
    fun requireUpdated(rowCount: Int) {
        if (rowCount == 0) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }
    }
}
