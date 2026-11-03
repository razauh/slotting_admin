package com.slotting.admin.observability

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind

data class AlphaTesterGateConfig(
    val enabled: Boolean,
    val allowlistedTesterIds: Set<String>,
) {
    init {
        require(allowlistedTesterIds.all(String::isNotBlank)) { "Allowlisted tester IDs must not be blank" }
    }

    companion object {
        val DISABLED = AlphaTesterGateConfig(enabled = false, allowlistedTesterIds = emptySet())
    }
}

interface AlphaTesterGate {
    fun assertTesterAllowed(principal: AuthenticatedPrincipal?)
}

class ConfiguredAlphaTesterGate(
    private val config: AlphaTesterGateConfig,
) : AlphaTesterGate {
    override fun assertTesterAllowed(principal: AuthenticatedPrincipal?) {
        if (!config.enabled) return
        val authenticated = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (authenticated.kind != PrincipalKind.PLAYER) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (authenticated.id !in config.allowlistedTesterIds) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
    }
}

object NoOpAlphaTesterGate : AlphaTesterGate {
    override fun assertTesterAllowed(principal: AuthenticatedPrincipal?) {}
}
