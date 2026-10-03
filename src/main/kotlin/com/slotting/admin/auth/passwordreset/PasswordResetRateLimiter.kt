package com.slotting.admin.auth.passwordreset

import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue

class PasswordResetRateLimiter(
    private val clock: Clock = Clock.systemUTC()
) {
    private val accountCooldown = ConcurrentHashMap<String, Instant>()
    private val accountRequests = ConcurrentHashMap<String, ConcurrentLinkedQueue<Instant>>()
    private val ipRequests = ConcurrentHashMap<String, ConcurrentLinkedQueue<Instant>>()
    private val tokenValidationAttempts = ConcurrentHashMap<String, ConcurrentLinkedQueue<Instant>>()

    data class RateLimitVerdict(
        val allowed: Boolean,
        val reason: String? = null
    )

    fun checkAndRecordRequest(
        accountKey: String,
        ipAddress: String,
        config: PasswordResetRateLimitConfig
    ): RateLimitVerdict {
        val now = clock.instant()

        // 1. IP rolling window check
        val ipQueue = ipRequests.computeIfAbsent(ipAddress) { ConcurrentLinkedQueue() }
        cleanQueue(ipQueue, now, Duration.ofMinutes(config.perIpWindowMinutes))
        if (ipQueue.size >= config.perIpMaxRequests) {
            return RateLimitVerdict(allowed = false, reason = "IP_RATE_LIMITED")
        }

        // 2. Account cooldown check (prevent rapid email bombing)
        val lastSend = accountCooldown[accountKey]
        if (lastSend != null && Duration.between(lastSend, now).toSeconds() < config.perAccountCooldownSeconds) {
            return RateLimitVerdict(allowed = false, reason = "ACCOUNT_COOLDOWN")
        }

        // 3. Account rolling limit
        val accQueue = accountRequests.computeIfAbsent(accountKey) { ConcurrentLinkedQueue() }
        cleanQueue(accQueue, now, Duration.ofMinutes(config.perAccountWindowMinutes))
        if (accQueue.size >= config.perAccountMaxRequests) {
            return RateLimitVerdict(allowed = false, reason = "ACCOUNT_RATE_LIMITED")
        }

        // Record request
        ipQueue.add(now)
        accQueue.add(now)
        accountCooldown[accountKey] = now

        return RateLimitVerdict(allowed = true)
    }

    fun checkAndRecordTokenVerification(ipAddress: String, maxPerMin: Int = 10): Boolean {
        val now = clock.instant()
        val queue = tokenValidationAttempts.computeIfAbsent(ipAddress) { ConcurrentLinkedQueue() }
        cleanQueue(queue, now, Duration.ofMinutes(1))
        if (queue.size >= maxPerMin) {
            return false
        }
        queue.add(now)
        return true
    }

    fun reset() {
        accountCooldown.clear()
        accountRequests.clear()
        ipRequests.clear()
        tokenValidationAttempts.clear()
    }

    private fun cleanQueue(queue: ConcurrentLinkedQueue<Instant>, now: Instant, window: Duration) {
        val cutoff = now.minus(window)
        while (queue.isNotEmpty() && queue.peek()?.isBefore(cutoff) == true) {
            queue.poll()
        }
    }
}
