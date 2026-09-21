package com.slotting.admin.validation.release

object ConnectedReleaseCiArtifactBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("pipeline accepts missing evidence")
        }
    }
}
