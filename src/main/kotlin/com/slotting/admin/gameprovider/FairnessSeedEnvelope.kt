package com.slotting.admin.gameprovider

import com.slotting.admin.secret.AesGcmEnvelopeEncryptor
import com.slotting.admin.secret.DecryptionTamperException
import com.slotting.admin.secret.EncryptedSecretPayload
import com.slotting.admin.secret.LocalDevMasterKeyProvider
import java.security.MessageDigest

data class SealedFairnessSeed(
    val ciphertextBase64: String,
    val nonceBase64: String,
    val keyId: String,
    val keyVersion: Int,
    val formatVersion: Int,
)

class FairnessSeedEnvelope(
    private val encryptor: AesGcmEnvelopeEncryptor,
    val keyId: String,
    val keyVersion: Int = 1,
) {
    init {
        require(keyId.isNotBlank()) { "fairness envelope keyId must not be blank" }
        require(keyVersion >= 1) { "fairness envelope keyVersion must be >= 1" }
    }

    private fun context(gameId: String, roundId: String, commitmentId: String): String =
        "GAME=$gameId|ROUND=$roundId|COMMITMENT=$commitmentId"

    fun seal(
        tenantId: String,
        gameId: String,
        roundId: String,
        commitmentId: String,
        plaintextSeed: String,
    ): SealedFairnessSeed {
        val payload = encryptor.encryptString(
            tenantId = tenantId,
            context = context(gameId, roundId, commitmentId),
            plaintext = plaintextSeed,
            keyVersion = keyVersion,
        )
        return SealedFairnessSeed(
            ciphertextBase64 = payload.ciphertextBase64,
            nonceBase64 = payload.ivBase64,
            keyId = keyId,
            keyVersion = payload.keyVersion,
            formatVersion = payload.formatVersion,
        )
    }

    fun open(
        tenantId: String,
        gameId: String,
        roundId: String,
        commitmentId: String,
        sealed: SealedFairnessSeed,
    ): String {
        if (!constantTimeEquals(sealed.keyId, keyId)) {
            throw DecryptionTamperException("Fairness envelope key ID mismatch")
        }
        val payload = EncryptedSecretPayload(
            ciphertextBase64 = sealed.ciphertextBase64,
            ivBase64 = sealed.nonceBase64,
            keyVersion = sealed.keyVersion,
            formatVersion = sealed.formatVersion,
        )
        return encryptor.decryptString(
            tenantId = tenantId,
            context = context(gameId, roundId, commitmentId),
            payload = payload,
        )
    }

    companion object {
        const val DEFAULT_KEY_ID = "fairness-local-dev"

        fun devDefault(): FairnessSeedEnvelope = FairnessSeedEnvelope(
            encryptor = AesGcmEnvelopeEncryptor(LocalDevMasterKeyProvider(), environment = "TEST"),
            keyId = DEFAULT_KEY_ID,
            keyVersion = 1,
        )

        fun constantTimeEquals(left: String, right: String): Boolean =
            MessageDigest.isEqual(left.toByteArray(Charsets.UTF_8), right.toByteArray(Charsets.UTF_8))
    }
}
