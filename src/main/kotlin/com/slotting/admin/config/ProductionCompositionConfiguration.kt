package com.slotting.admin.config

import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.ledger.LedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.provider.PaymentMethodStore
import com.slotting.admin.rg.DurableResponsibleGamingService
import com.slotting.admin.rg.DurableResponsibleGamingStore
import com.slotting.admin.withdrawal.AuthoritativeWithdrawalService
import com.slotting.admin.withdrawal.AuthoritativeWithdrawalStore
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import java.time.Clock

/**
 * Production Spring composition wiring durable services, repositories,
 * security filters, workers, and fail-closed readiness (TC-040, BE-002, XREP-001).
 */

@Configuration
class ProductionCompositionConfiguration {

    @Bean
    @ConditionalOnMissingBean
    fun systemClock(): Clock = Clock.systemUTC()

    @Bean
    @ConditionalOnMissingBean
    fun ledgerPostingService(store: LedgerJournalStore, clock: Clock): LedgerPostingService =
        LedgerPostingService(store = store, clock = clock)

    @Bean
    @ConditionalOnMissingBean
    fun authoritativeWithdrawalService(
        withdrawalStore: AuthoritativeWithdrawalStore,
        paymentMethodStore: PaymentMethodStore,
        sessions: AdminSessionDirectory,
        clock: Clock,
    ): AuthoritativeWithdrawalService = AuthoritativeWithdrawalService(
        withdrawalStore = withdrawalStore,
        paymentMethodStore = paymentMethodStore,
        sessions = sessions,
        clock = clock,
    )

    @Bean
    @ConditionalOnMissingBean
    fun durableResponsibleGamingService(
        store: DurableResponsibleGamingStore,
        clock: Clock,
    ): DurableResponsibleGamingService = DurableResponsibleGamingService(
        store = store,
        clock = clock,
    )
}
