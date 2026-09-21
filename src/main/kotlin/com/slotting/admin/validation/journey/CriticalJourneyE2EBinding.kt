package com.slotting.admin.validation.journey

object CriticalJourneyE2EBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("prove baseline blocked")
        }
    }
}
