package com.slotting.admin.validation.rehearsal

object RestoreReplayMigrationRehearsalBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("checksum/balance/event gaps")
        }
    }
}
