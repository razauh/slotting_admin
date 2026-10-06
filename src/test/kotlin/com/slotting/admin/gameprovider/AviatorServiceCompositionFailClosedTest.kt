package com.slotting.admin.gameprovider

import com.slotting.admin.config.AviatorServiceCompositionConfiguration
import com.slotting.admin.identity.InMemoryServerEligibilityStore
import com.slotting.admin.identity.PlayerRegistrationStore
import com.slotting.admin.identity.ServerEligibilityStore
import com.slotting.admin.ledger.LedgerPostingService
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.springframework.boot.test.context.runner.ApplicationContextRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.transaction.PlatformTransactionManager
import java.time.Clock
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AviatorServiceCompositionFailClosedTest {

    @Configuration
    class StubDependencies {
        @Bean
        fun store(): DurableGameWagerAndSettlementStore = Mockito.mock(DurableGameWagerAndSettlementStore::class.java)

        @Bean
        fun ledgerPostingService(): LedgerPostingService = Mockito.mock(LedgerPostingService::class.java)

        @Bean
        fun registrationStore(): PlayerRegistrationStore = Mockito.mock(PlayerRegistrationStore::class.java)

        @Bean
        fun fairnessAuthority(): ProvablyFairOutcomeAuthority = Mockito.mock(ProvablyFairOutcomeAuthority::class.java)

        @Bean
        fun clock(): Clock = Clock.systemUTC()
    }

    @Configuration
    class EligibilityStub {
        @Bean
        fun eligibilityStore(): ServerEligibilityStore = InMemoryServerEligibilityStore()
    }

    @Configuration
    class TransactionManagerStub {
        @Bean
        fun transactionManager(): PlatformTransactionManager = Mockito.mock(PlatformTransactionManager::class.java)
    }

    private fun runner(vararg configuration: Class<*>): ApplicationContextRunner =
        ApplicationContextRunner().withUserConfiguration(AviatorServiceCompositionConfiguration::class.java, *configuration)

    @Test
    fun `disabled composition exposes no durable wager service`() {
        runner(StubDependencies::class.java).run { context ->
            assertTrue(
                context.getBeansOfType(DurableGameWagerAndSettlementService::class.java).isEmpty(),
                "Disabled composition must not expose the wager service",
            )
        }
    }

    @Test
    fun `enabled composition without an eligibility store fails closed`() {
        runner(StubDependencies::class.java, TransactionManagerStub::class.java)
            .withPropertyValues("slotting.aviator.service.enabled=true")
            .run { context ->
                val failure = assertNotNull(context.startupFailure, "Missing ServerEligibilityStore must fail the context")
                assertTrue(rootMessage(failure).contains("ServerEligibilityStore"), "Failure must identify ServerEligibilityStore: ${rootMessage(failure)}")
            }
    }

    @Test
    fun `enabled composition without a transaction manager fails closed`() {
        runner(StubDependencies::class.java, EligibilityStub::class.java)
            .withPropertyValues("slotting.aviator.service.enabled=true")
            .run { context ->
                val failure = assertNotNull(context.startupFailure, "Missing PlatformTransactionManager must fail the context")
                assertTrue(rootMessage(failure).contains("PlatformTransactionManager"), "Failure must identify PlatformTransactionManager: ${rootMessage(failure)}")
            }
    }

    @Test
    fun `enabled composition with required beans creates the durable wager service`() {
        runner(StubDependencies::class.java, EligibilityStub::class.java, TransactionManagerStub::class.java)
            .withPropertyValues("slotting.aviator.service.enabled=true")
            .run { context ->
                assertTrue(
                    context.getBeansOfType(DurableGameWagerAndSettlementService::class.java).isNotEmpty(),
                    "Enabled composition with all dependencies must create the wager service",
                )
            }
    }

    private fun rootMessage(throwable: Throwable): String {
        val builder = StringBuilder()
        var cause: Throwable? = throwable
        while (cause != null) {
            builder.append(cause.message).append(' ')
            cause = cause.cause
        }
        return builder.toString()
    }
}
