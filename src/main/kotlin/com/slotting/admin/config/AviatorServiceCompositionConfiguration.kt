package com.slotting.admin.config

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.aml.PlayAbuseDetectionStore
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.auth.DurableAuthService
import com.slotting.admin.gameprovider.AuthoritativeGameSnapshotAndEventService
import com.slotting.admin.gameprovider.DurableGameWagerAndSettlementService
import com.slotting.admin.gameprovider.DurableGameWagerAndSettlementStore
import com.slotting.admin.gameprovider.FairnessEvidenceStore
import com.slotting.admin.gameprovider.GameEventDispatcher
import com.slotting.admin.gameprovider.GameEventJournalStore
import com.slotting.admin.gameprovider.ProvablyFairOutcomeAuthority
import com.slotting.admin.identity.PlayerRegistrationStore
import com.slotting.admin.identity.ServerEligibilityStore
import com.slotting.admin.ledger.LedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.LegacyIsoCurrencyPostingPolicy
import com.slotting.admin.wallet.AuthoritativeWalletService
import io.micrometer.core.instrument.MeterRegistry
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
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

    @Bean("legacyGameLedgerPostingService")
    @ConditionalOnBean(LedgerJournalStore::class)
    fun legacyGameLedgerPostingService(store: LedgerJournalStore, clock: Clock): LedgerPostingService =
        LedgerPostingService(store = store, clock = clock, currencyPolicy = LegacyIsoCurrencyPostingPolicy)

    @Bean
    @ConditionalOnMissingBean
    fun durableGameWagerAndSettlementService(
        store: DurableGameWagerAndSettlementStore,
        legacyGameLedgerPostingService: LedgerPostingService,
        registrationStore: PlayerRegistrationStore,
        eligibilityStore: ServerEligibilityStore,
        aviatorSystemPrincipal: AuthenticatedPrincipal,
        fairnessAuthority: ProvablyFairOutcomeAuthority,
        clock: Clock,
        transactionManager: PlatformTransactionManager,
        meterRegistry: ObjectProvider<MeterRegistry>,
        playAbuseDetectionStore: PlayAbuseDetectionStore,
    ): DurableGameWagerAndSettlementService = DurableGameWagerAndSettlementService(
        store = store,
        ledgerService = legacyGameLedgerPostingService,
        registrationStore = registrationStore,
        eligibilityStore = eligibilityStore,
        adminPrincipal = aviatorSystemPrincipal,
        clock = clock,
        fairnessAuthority = fairnessAuthority,
        txManager = transactionManager,
        meterRegistry = meterRegistry.getIfAvailable(),
        playAbuseDetectionStore = playAbuseDetectionStore,
    )

    @Bean
    @ConditionalOnBean(AuthoritativeWalletService::class, LedgerJournalStore::class, FairnessEvidenceStore::class, GameEventJournalStore::class)
    @ConditionalOnMissingBean
    fun authoritativeGameSnapshotAndEventService(
        gameStore: DurableGameWagerAndSettlementStore,
        gameService: DurableGameWagerAndSettlementService,
        walletService: AuthoritativeWalletService,
        ledgerStore: LedgerJournalStore,
        fairnessStore: FairnessEvidenceStore,
        eventJournalStore: GameEventJournalStore,
        registrationStore: PlayerRegistrationStore,
        clock: Clock,
        transactionManager: PlatformTransactionManager,
        authService: ObjectProvider<DurableAuthService>,
        eventDispatcher: ObjectProvider<GameEventDispatcher>,
    ): AuthoritativeGameSnapshotAndEventService = AuthoritativeGameSnapshotAndEventService(
        gameStore = gameStore,
        gameService = gameService,
        walletService = walletService,
        ledgerStore = ledgerStore,
        fairnessStore = fairnessStore,
        eventJournalStore = eventJournalStore,
        registrationStore = registrationStore,
        clock = clock,
        authService = authService.getIfAvailable(),
        txManager = transactionManager,
        eventDispatcher = eventDispatcher.getIfAvailable(),
    )
}
