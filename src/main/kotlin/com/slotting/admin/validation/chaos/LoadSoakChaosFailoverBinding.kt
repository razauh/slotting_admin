package com.slotting.admin.validation.chaos

object LoadSoakChaosFailoverBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("establish failure thresholds")
        }
    }
}
