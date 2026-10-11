package com.slotting.admin.gameprovider

import org.springframework.stereotype.Service
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.support.TransactionTemplate
import java.time.Clock
import java.util.concurrent.ConcurrentHashMap

@Service
class AviatorEventDeliveryRecovery(
    private val gameStore: DurableGameWagerAndSettlementStore,
    private val eventJournalStore: GameEventJournalStore,
    private val snapshotService: AuthoritativeGameSnapshotAndEventService,
    private val leaseStore: GameLifecycleLeaseStore? = null,
    private val txManager: PlatformTransactionManager? = null,
    private val clock: Clock = Clock.systemUTC(),
) {
    private val locks = ConcurrentHashMap<String, Any>()

    fun repairLatest(
        tenantId: String,
        gameId: String,
        token: LifecycleLeaseToken? = null,
    ): GameEventRecord? {
        val key = "$tenantId:$gameId"
        return synchronized(locks.computeIfAbsent(key) { Any() }) {
            val repair = {
                verifyLease(tenantId, gameId, token)
                val round = gameStore.findLatestRound(tenantId, gameId)
                if (round == null) {
                    null
                } else {
                    val existing = eventJournalStore.findEventByIdentity(
                        tenantId, gameId, round.roundId, round.roundVersion, "gameState"
                    )
                    if (existing != null) {
                        existing
                    } else {
                        snapshotService.recordAndBroadcastGameState(
                            tenantId = tenantId,
                            gameId = gameId,
                            roundId = round.roundId,
                            phase = round.phase,
                            multiplier = round.currentMultiplier,
                            roundVersion = round.roundVersion,
                            elapsedFlightSeconds = FlightClock.computeElapsedFlightSeconds(round, clock),
                        )
                    }
                }
            }
            txManager?.let { TransactionTemplate(it).execute { repair() } } ?: repair()
        }
    }

    private fun verifyLease(tenantId: String, gameId: String, token: LifecycleLeaseToken?) {
        val store = leaseStore ?: return
        val required = token ?: throw LifecycleNotOwnerException(
            LifecycleNotOwnerReason.LEASE_MISSING,
            "Event recovery for $tenantId/$gameId requires an active lease token",
        )
        val lease = store.lockAndVerify(tenantId, gameId, required.ownerId, required.epoch)
            ?: throw LifecycleNotOwnerException(
                LifecycleNotOwnerReason.LEASE_EXPIRED_OR_SUPERSEDED,
                "Event recovery for $tenantId/$gameId rejected: lease is no longer current",
            )
        check(lease.ownerId == required.ownerId && lease.epoch == required.epoch)
    }
}
