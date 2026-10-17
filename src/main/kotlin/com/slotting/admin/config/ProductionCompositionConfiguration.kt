package com.slotting.admin.config

import com.slotting.admin.auth.*
import com.slotting.admin.deposit.*
import com.slotting.admin.identity.*
import com.slotting.admin.ledger.*
import com.slotting.admin.provider.*
import com.slotting.admin.provider.port.EncryptedProviderCredentialsStore
import com.slotting.admin.provider.port.JdbcEncryptedProviderCredentialsStore
import com.slotting.admin.provider.port.KmsProviderCredentialsResolver
import com.slotting.admin.provider.port.ProviderCredentialsResolver
import com.slotting.admin.rg.*
import com.slotting.admin.secret.KmsBackendSecretsService
import com.slotting.admin.wallet.*
import com.slotting.admin.withdrawal.*
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.beans.factory.ObjectProvider
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.JdbcTemplate
import io.micrometer.core.instrument.MeterRegistry
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
    fun durableDepositWorkflowService(
        workflowStore: DepositWorkflowStore,
        paymentMethodStore: PaymentMethodStore,
        sessions: AdminSessionDirectory,
        ledgerPostingService: LedgerPostingService,
        clock: Clock,
        credentialsResolver: ObjectProvider<ProviderCredentialsResolver>,
        meterRegistry: ObjectProvider<MeterRegistry>,
    ): DurableDepositWorkflowService = DurableDepositWorkflowService(
        workflowStore = workflowStore,
        paymentMethodStore = paymentMethodStore,
        sessions = sessions,
        ledgerPostingService = ledgerPostingService,
        credentialsResolver = credentialsResolver.getIfAvailable() ?: ProviderCredentialsResolver { _, _ -> null },
        clock = clock,
        meterRegistry = meterRegistry.getIfAvailable(),
    )

    @Bean
    @ConditionalOnMissingBean
    fun encryptedProviderCredentialsStore(jdbc: JdbcTemplate): EncryptedProviderCredentialsStore =
        JdbcEncryptedProviderCredentialsStore(jdbc)

    @Bean
    @ConditionalOnBean(KmsBackendSecretsService::class)
    @ConditionalOnMissingBean(ProviderCredentialsResolver::class)
    fun providerCredentialsResolver(
        kms: KmsBackendSecretsService,
        store: EncryptedProviderCredentialsStore,
    ): ProviderCredentialsResolver = KmsProviderCredentialsResolver(kms, store)

    @Bean
    @ConditionalOnMissingBean
    fun paymentMethodQueryService(
        paymentMethodStore: PaymentMethodStore,
        sessions: AdminSessionDirectory,
        clock: Clock,
    ): PaymentMethodQueryService = PaymentMethodQueryService(
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
