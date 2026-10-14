package com.slotting.admin.auth

import com.slotting.admin.auth.passwordreset.PasswordResetConfig
import com.slotting.admin.auth.passwordreset.PasswordResetTokenCrypto
import java.io.File
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class PasswordResetPepperContractTest {
    @Test
    fun startupWithoutExplicitPepperFailsInEveryMode() {
        listOf(false, true).forEach { production ->
            assertFailsWith<IllegalArgumentException> {
                PasswordResetConfig(hmacSecret = "", isProduction = production)
            }
        }
    }

    @Test
    fun shortAndDenylistedPeppersAreRejectedInEveryMode() {
        listOf(false, true).forEach { production ->
            assertFailsWith<IllegalArgumentException> {
                PasswordResetConfig(hmacSecret = "short", isProduction = production)
            }
            assertFailsWith<IllegalArgumentException> {
                PasswordResetConfig(hmacSecret = "default-secret", isProduction = production)
            }
        }
    }

    @Test
    fun defaultPepperLiteralIsAbsentAndRotationChangesTokenDigest() {
        val configSource = File("src/main/kotlin/com/slotting/admin/auth/passwordreset/PasswordResetConfig.kt").readText()
        assertTrue(!configSource.contains("secure-password-reset-pepper-32-bytes-minimum-entropy"))
        val token = "synthetic-reset-token"
        val oldDigest = PasswordResetTokenCrypto.computeDigest(token, "old-pepper-with-at-least-32-characters")
        val newDigest = PasswordResetTokenCrypto.computeDigest(token, "new-pepper-with-at-least-32-characters")
        assertNotEquals(oldDigest, newDigest)
    }
}
