package com.slotting.admin.rails

import com.slotting.admin.ledger.LedgerPostingService
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.JdbcTemplate

@Configuration
class RailsHttpConfiguration {
    @Bean
    fun manualRailsReceiptService(): ManualRailsReceiptService = ManualRailsReceiptService()

    @Bean
    fun ledgerDepositCreditPoster(ledgerPostingService: LedgerPostingService): LedgerDepositCreditPoster =
        LedgerDepositCreditPoster(ledgerPostingService)

    @Bean
    fun payoutLedgerDebitPoster(ledgerPostingService: LedgerPostingService): PayoutLedgerDebitPoster =
        PayoutLedgerDebitPoster(ledgerPostingService)

    @Bean
    fun depositSubmissionRepository(jdbc: JdbcTemplate): DepositSubmissionRepository =
        JdbcDepositSubmissionRepository { jdbc.dataSource.connection }

    @Bean
    fun payoutRequestRepository(jdbc: JdbcTemplate): PayoutRequestRepository =
        JdbcPayoutRequestRepository { jdbc.dataSource.connection }
}
