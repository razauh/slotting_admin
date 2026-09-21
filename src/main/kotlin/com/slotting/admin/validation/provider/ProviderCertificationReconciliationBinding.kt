package com.slotting.admin.validation.provider

object ProviderCertificationReconciliationBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("certification cases fail")
        }
    }
}
