package com.slotting.admin.attestation

/**
 * Pluggable external attestation verifier boundary.
 *
 * In accordance with TC-033:
 * The core domain depends on this provider-independent abstraction rather than a Google-specific implementation.
 * Optional external adapters (e.g. Google Play Integrity or hardware tokens) may be plugged in without
 * changing challenge issuance, session binding, or replay protection.
 */
interface OperationAttestationVerifier {
    fun verify(challenge: OperationChallengeRecord, payload: OperationAttestationPayload): ExternalAttestationVerdict
}

sealed class ExternalAttestationVerdict {
    /**
     * Default approved baseline: no external device-integrity provider is configured.
     * The backend operates under provider-independent operation-bound challenge semantics.
     */
    data object NotConfigured : ExternalAttestationVerdict()

    data class Verified(
        val providerName: String,
        val trustLevel: String,
        val details: String,
    ) : ExternalAttestationVerdict()

    data class Rejected(
        val reason: String,
        val details: String,
    ) : ExternalAttestationVerdict()

    data class Unavailable(
        val reason: String,
    ) : ExternalAttestationVerdict()
}

/**
 * Marker interface for test-only or simulated verifiers.
 * Production composition MUST reject any verifier implementing this interface.
 */
interface TestOnlyVerifierMarker

/**
 * Provider-independent default verifier for production without external Google Play dependencies.
 */
class ProviderIndependentAttestationVerifier : OperationAttestationVerifier {
    override fun verify(challenge: OperationChallengeRecord, payload: OperationAttestationPayload): ExternalAttestationVerdict {
        return ExternalAttestationVerdict.NotConfigured
    }
}

/**
 * Insecure test-only verifier used exclusively in characterization tests to verify production composition guardrails.
 */
class InsecureAlwaysAllowTestVerifier : OperationAttestationVerifier, TestOnlyVerifierMarker {
    override fun verify(challenge: OperationChallengeRecord, payload: OperationAttestationPayload): ExternalAttestationVerdict {
        return ExternalAttestationVerdict.Verified(
            providerName = "TEST_FAKE",
            trustLevel = "TEST_ALWAYS_ALLOW",
            details = "Insecure test adapter"
        )
    }
}
