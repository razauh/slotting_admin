package com.slotting.admin.worker

import io.micrometer.core.instrument.MeterRegistry
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.scheduling.annotation.Scheduled

@Configuration
@ConditionalOnProperty(
    prefix = "slotting.outbox.worker",
    name = ["enabled"],
    havingValue = "true",
    matchIfMissing = false,
)
@EnableScheduling
class DurableWorkerConfiguration {
    @Bean
    fun leasedOutboxWorker(
        store: LeasedOutboxStore,
        broker: WorkerOutboxBrokerSink,
        alerts: WorkerOutboxAlertSink,
        observability: OutboxWorkerObservability,
    ): LeasedOutboxWorkerService = LeasedOutboxWorkerService(
        store = store,
        broker = broker,
        alertSink = alerts,
        observability = observability,
    )

    @Bean
    @ConditionalOnBean(MeterRegistry::class)
    fun durableWorkerObservability(registry: MeterRegistry): OutboxWorkerObservability = MicrometerOutboxWorkerObservability(registry)

    @Bean
    @ConditionalOnMissingBean(OutboxWorkerObservability::class)
    fun loggingWorkerObservability(): OutboxWorkerObservability = LoggingOutboxWorkerObservability()

    @Bean
    @ConditionalOnMissingBean(WorkerOutboxAlertSink::class)
    fun loggingWorkerAlerts(): WorkerOutboxAlertSink = LoggingWorkerOutboxAlertSink()

    @Bean
    @ConditionalOnMissingBean(WorkerOutboxBrokerSink::class)
    fun loggingWorkerBrokerSink(): WorkerOutboxBrokerSink = LoggingWorkerOutboxBrokerSink()

    @Bean
    fun scheduledOutboxDispatcher(worker: LeasedOutboxWorkerService, store: LeasedOutboxStore): ScheduledOutboxDispatcher =
        ScheduledOutboxDispatcher(worker, store)
}

class ScheduledOutboxDispatcher(
    private val worker: LeasedOutboxWorkerService,
    private val store: LeasedOutboxStore,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    @Scheduled(fixedDelayString = "\${slotting.outbox.worker.fixed-delay-ms:1000}")
    fun dispatch() {
        runCatching {
            store.tenantsWithPendingWork().forEach { tenantId ->
                worker.pollAndProcess(
                    PollAndProcessOutboxCommand(
                        tenantId = tenantId,
                        workerId = "spring-scheduled-outbox",
                        batchSize = 50,
                        leaseDurationSeconds = 30,
                        correlationId = "scheduled-outbox-dispatch",
                        causationId = "spring-scheduler",
                    ),
                )
            }
        }.onFailure { failure ->
            logger.warn("outbox_worker_cycle_failed failureType={}", failure::class.simpleName)
        }
    }
}

class MicrometerOutboxWorkerObservability(private val registry: MeterRegistry) : OutboxWorkerObservability {
    override fun recordMetric(event: OutboxWorkerMetricEvent) {
        registry.counter("admin.outbox.events", "event_type", event.eventType, "outcome", event.outcome).increment()
        event.details["oldestAgeSeconds"]?.let { age ->
            (age as? Number)?.toDouble()?.let { registry.gauge("admin.outbox.oldest_age_seconds", it) }
        }
    }

    override fun getMetrics(): List<OutboxWorkerMetricEvent> = emptyList()
}

class LoggingOutboxWorkerObservability : OutboxWorkerObservability {
    private val logger = LoggerFactory.getLogger(javaClass)

    override fun recordMetric(event: OutboxWorkerMetricEvent) {
        logger.info(
            "outbox_worker_metric eventType={} tenantId={} eventId={} outcome={} correlationId={} causationId={}",
            event.eventType,
            event.tenantId,
            event.eventId,
            event.outcome,
            event.correlationId,
            event.causationId,
        )
    }

    override fun getMetrics(): List<OutboxWorkerMetricEvent> = emptyList()
}

class LoggingWorkerOutboxAlertSink : WorkerOutboxAlertSink {
    private val logger = LoggerFactory.getLogger(javaClass)

    override fun emitAlert(alert: WorkerOutboxAlert) {
        logger.warn(
            "outbox_worker_alert tenantId={} eventId={} reason={}",
            alert.tenantId,
            alert.eventId,
            alert.reason,
        )
    }

    override fun getAlerts(): List<WorkerOutboxAlert> = emptyList()
}

class LoggingWorkerOutboxBrokerSink : WorkerOutboxBrokerSink {
    private val logger = LoggerFactory.getLogger(javaClass)

    override fun publish(event: LeasedOutboxEventRecord) {
        logger.info(
            "outbox_event_published eventId={} tenantId={} topic={}",
            event.eventId,
            event.tenantId,
            event.topic,
        )
    }
}
