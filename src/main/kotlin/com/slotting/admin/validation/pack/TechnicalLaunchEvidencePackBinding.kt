package com.slotting.admin.validation.pack

object TechnicalLaunchEvidencePackBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("missing/stale item rejected")
        }
    }
}
