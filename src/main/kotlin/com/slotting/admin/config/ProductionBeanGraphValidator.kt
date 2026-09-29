package com.slotting.admin.config

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.config.BeanFactoryPostProcessor
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory
import org.springframework.core.env.Environment
import org.springframework.stereotype.Component

/**
 * Validates the Spring Bean graph on startup (TC-040, BE-002, XREP-001).
 * In production profile, strictly bans any authoritative bean implementing or matching
 * InMemory*, Fake*, or Sandbox* implementations.
 */
@Component
class ProductionBeanGraphValidator(
    private val activeProfile: String? = null,
    private val environment: Environment? = null,
) : BeanFactoryPostProcessor {

    private val log = LoggerFactory.getLogger(javaClass)

    companion object {
        private val BANNED_PATTERNS = listOf(
            Regex(".*InMemory.*(Store|Service|Directory|Queue|Sink|Gate).*"),
            Regex(".*Fake.*(Store|Service|Directory|Queue|Adapter|Port|Signing|Target|Verifier|Gate).*"),
            Regex(".*Sandbox.*(Store|Service|Directory|Queue|Adapter).*"),
            Regex(".*(AlwaysValid|AlwaysApproved|AlwaysHealthy).*"),
        )
    }

    override fun postProcessBeanFactory(beanFactory: ConfigurableListableBeanFactory) {
        val isProduction = activeProfile == "production" ||
                (environment?.activeProfiles?.contains("production") == true)

        if (!isProduction) {
            log.info("ProductionBeanGraphValidator skipped: not running in production profile")
            return
        }

        log.info("Validating production bean graph for banned fake/in-memory authoritative implementations...")

        for (beanName in beanFactory.beanDefinitionNames) {
            val beanDefinition = beanFactory.getBeanDefinition(beanName)
            val className = beanDefinition.beanClassName
                ?: beanFactory.getType(beanName)?.name
                ?: continue

            for (pattern in BANNED_PATTERNS) {
                if (pattern.matches(className)) {
                    val errorMsg = "Authoritative bean '$beanName' with class '$className' matches prohibited pattern '$pattern' and is prohibited in production profile! (TC-040 fail-closed invariant)"
                    log.error(errorMsg)
                    throw IllegalStateException(errorMsg)
                }
            }
        }

        // Also check any already instantiated singletons
        for (singletonName in beanFactory.singletonNames) {
            val singleton = beanFactory.getSingleton(singletonName) ?: continue
            val className = singleton.javaClass.name
            for (pattern in BANNED_PATTERNS) {
                if (pattern.matches(className)) {
                    val errorMsg = "Authoritative singleton '$singletonName' with class '$className' matches prohibited pattern '$pattern' and is prohibited in production profile! (TC-040 fail-closed invariant)"
                    log.error(errorMsg)
                    throw IllegalStateException(errorMsg)
                }
            }
        }

        log.info("Production bean graph validation passed: 0 banned fakes or memory stores detected.")
    }
}
