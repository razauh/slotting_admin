package com.slotting.admin.validation.device

object PhysicalDeviceMatrixBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("record matrix failures")
        }
    }
}
