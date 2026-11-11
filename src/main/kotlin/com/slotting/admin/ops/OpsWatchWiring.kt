package com.slotting.admin.ops

import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.scheduling.annotation.EnableScheduling

@Configuration
@EnableScheduling
@ConditionalOnProperty(prefix = "ops.watch", name = ["schedule-enabled"], havingValue = "true")
class OpsWatchWiring(
    private val dataSource: javax.sql.DataSource,

    @Value("\${SUPABASE_URL:}") private val baseUrl: String,
    @Value("\${SUPABASE_ANON_KEY:}") private val anonKey: String,
    @Value("\${SLOTTING_SUPABASE_JWT_SECRET:}") private val jwtSecret: String,
    @Value("\${SLOTTING_REALTIME_HINTS_ENABLED:false}") private val hintsEnabled: Boolean,
) {
    @Bean
    fun opsLiveProbes(): OpsLiveProbes = OpsLiveProbes(baseUrl, anonKey, jwtSecret)

    @Bean
    fun opsWatchService(repository: OpsNoticeRepository): OpsWatchService = OpsWatchService(repository)

    @Bean
    fun opsDetectorRunner(service: OpsWatchService): OpsDetectorRunner = OpsDetectorRunner(service)

    @Bean
    fun opsWatchState(): OpsWatchState = JdbcOpsWatchState { dataSource.connection }

    @Bean
    fun opsWatchCatchup(state: OpsWatchState, scheduler: OpsWatchScheduler): OpsWatchCatchup =
        OpsWatchCatchup(state, scheduler, enabled = true)

    @Bean
    fun opsWatchScheduler(runner: OpsDetectorRunner, probes: OpsLiveProbes): OpsWatchScheduler =
        OpsWatchScheduler(
            runner = runner,
            jwtProbe = { probes.edgeStatus() },
            jwksHash = { probes.jwksHash() },
            exposureProbe = { probes.rootStatus() },
            budgetState = { hintsEnabled },
            retentionCounts = { Triple(0, 0, 0) },
            matrixProbe = null,
        )
}
