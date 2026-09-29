package com.slotting.admin.release

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID

data class SigningKeyPair(
    val keyAlias: String,
    val publicKey: String,
    val privateKey: String,
    val isTestOnly: Boolean,
)

class SigningTrustStore(
    val trustedKeys: Map<String, String>,
    val testKeyAliases: Set<String> = emptySet(),
    val allowTestKeysInProduction: Boolean = false,
) {
    fun getPublicKey(keyAlias: String): String? = trustedKeys[keyAlias]

    fun isTestKey(keyAlias: String): Boolean = testKeyAliases.contains(keyAlias)
}

/**
 * OpenBao Transit key-management client abstraction (TC-041).
 * In production, requests signatures over artifact digests via OpenBao Transit API.
 * The private signing key never leaves the OpenBao secure boundary.
 */
interface OpenBaoTransitSigningClient {
    fun signDigest(keyName: String, digestSha256: String): ReleaseSignature
    fun verifySignature(keyName: String, digestSha256: String, signature: String): Boolean
}

/**
 * Deterministic signing authority utility for tests and verification simulation (TC-041).
 */
object TestSigningAuthority {

    fun generateKeyPair(keyAlias: String = "bao-transit-key-1", isTestOnly: Boolean = false): SigningKeyPair {
        val rand = UUID.randomUUID().toString()
        val pub = "pub-key-$rand"
        val priv = "priv-key-$rand"
        return SigningKeyPair(keyAlias, pub, priv, isTestOnly)
    }

    fun sign(data: String, privateKey: String): String {
        val combined = "$data:$privateKey"
        val digest = MessageDigest.getInstance("SHA-256").digest(combined.toByteArray(StandardCharsets.UTF_8))
        return "sig:" + Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    fun verify(data: String, signature: String, publicKey: String): Boolean {
        // In this test authority simulator, we verify that the signature corresponds to the data and key pair
        // If the signature is "sig:" + hash of data + matching private key
        if (!signature.startsWith("sig:")) return false
        val expectedSuffix = publicKey.removePrefix("pub-key-")
        val privCandidate = "priv-key-$expectedSuffix"
        val expectedSig = sign(data, privCandidate)
        return signature == expectedSig
    }
}
