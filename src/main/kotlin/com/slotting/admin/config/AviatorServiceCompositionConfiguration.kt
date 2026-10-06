package com.slotting.admin.config

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.gameprovider.DurableGameWagerAndSettlementService
import com.slotting.admin.gameprovider.DurableGameWagerAndSettlementStore
import com.slotting.admin.gameprovider.ProvablyFairOutcomeAuthority
import com.slotting.admin.identity.PlayerRegistrationStore
import com.slotting.admin.identity.ServerEligibilityStore
import com.slotting.admin.ledger.LedgerPostingService
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.transaction.PlatformTransactionManager
import java.time.Clock

@Configuration
@ConditionalOnProperty(
    prefix = "slotting.aviator.service",
    name = ["enabled"],
    havingValue = "true",
    matchIfMissing = false,
)
class AviatorServiceCompositionConfiguration {

    @Bean
    @ConditionalOnMissingBean
    fun aviatorSystemPrincipal(): AuthenticatedPrincipal = AuthenticatedPrincipal(
        id = "system-aviator-service",
        tenantId = "system",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    @Bean
    @ConditionalOnMissingBean
    fun durableGameWagerAndSettlementService(
        store: DurableGameWagerAndSettlementStore,
        ledgerPostingService: LedgerPostingService,
        registrationStore: PlayerRegistrationStore,
        eligibilityStore: ServerEligibilityStore,
        aviatorSystemPrincipal: AuthenticatedPrincipal,
        fairnessAuthority: ProvablyFairOutcomeAuthority,
        clock: Clock,
        transactionManager: PlatformTransactionManager,
    ): DurableGameWagerAndSettlementService = DurableGameWagerAndSettlementService(
        store = store,
        ledgerService = ledgerPostingService,
        registrationStore = registrationStore,
        eligibilityStore = eligibilityStore,
        adminPrincipal = aviatorSystemPrincipal,
        clock = clock,
        fairnessAuthority = fairnessAuthority,
        txManager = transactionManager,
    )
}
