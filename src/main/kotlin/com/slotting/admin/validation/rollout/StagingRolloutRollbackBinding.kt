package com.slotting.admin.validation.rollout

object StagingRolloutRollbackBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("smoke/rollback/page drill fails")
        }
    }
}
