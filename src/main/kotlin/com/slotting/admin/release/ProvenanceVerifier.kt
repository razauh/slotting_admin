package com.slotting.admin.release

import java.time.Clock
import java.time.Duration
import java.time.Instant

data class ProvenanceVerificationResult(
    val isValid: Boolean,
    val reasons: List<String>,
)

/**
 * Fail-closed provenance and release evidence verifier (TC-041, BE-032, BE-034).
 * Enforces cryptographic signature verification, digest validation, trusted issuer checks,
 * clean git commit verification, and bans test signing authorities from production.
 */
class ProvenanceVerifier(
    private val trustStore: SigningTrustStore,
    private val expectedRepository: String? = null,
    private val maxEvidenceAge: Duration = Duration.ofDays(7),
    private val clock: Clock = Clock.systemUTC(),
) {

    companion object {
        const val AUTHORITATIVE_RESTORE_ISSUER = "AUTHORITATIVE_BACKUP_RECOVERY_ENGINE"
    }

    fun verify(manifest: ReleaseEvidenceManifest, targetEnvironment: Environment): ProvenanceVerificationResult {
        val reasons = mutableListOf<String>()

        // 1. Resolve trusted public key
        val publicKey = trustStore.getPublicKey(manifest.signature.keyAlias)
        if (publicKey == null) {
            reasons.add("Unknown or untrusted signing key alias: ${manifest.signature.keyAlias}")
            return ProvenanceVerificationResult(false, reasons)
        }

        // 2. Reject test signing authorities in production
        if (targetEnvironment == Environment.PRODUCTION && trustStore.isTestKey(manifest.signature.keyAlias) && !trustStore.allowTestKeysInProduction) {
            reasons.add("Test signing authority prohibited in production environment: ${manifest.signature.keyAlias}")
        }

        // 3. Cryptographic signature verification over canonical payload
        val signingPayload = manifest.toSigningPayload()
        val signatureValid = TestSigningAuthority.verify(signingPayload, manifest.signature.signatureValue, publicKey)
        if (!signatureValid) {
            reasons.add("Signature or digest mismatch: release payload has been tampered or signing key does not match")
        }

        // 4. Dirty git checkout rejection
        if (!manifest.commit.isClean) {
            reasons.add("Working directory was dirty at build time for commit ${manifest.commit.commitSha}")
        }

        // 5. Repository boundary check
        if (expectedRepository != null && manifest.commit.repository != expectedRepository) {
            reasons.add("Commit repository mismatch: expected '$expectedRepository' but manifest asserted '${manifest.commit.repository}'")
        }

        // 6. Schema migration verification check
        if (!manifest.migration.allVerified || !manifest.migration.testedAgainstEphemeralPostgres) {
            reasons.add("Flyway schema migrations failed verification or were not tested against ephemeral PostgreSQL")
        }

        // 7. Restore drill verification
        if (manifest.restoreDrill != null) {
            if (manifest.restoreDrill.issuerSubsystem != AUTHORITATIVE_RESTORE_ISSUER) {
                reasons.add("Untrusted issuer for restore drill receipt: expected '$AUTHORITATIVE_RESTORE_ISSUER' but found '${manifest.restoreDrill.issuerSubsystem}'")
            }
            if (!manifest.restoreDrill.ledgerReconciled) {
                reasons.add("Restore drill failed authoritative financial ledger reconciliation")
            }
        } else if (targetEnvironment == Environment.PRODUCTION) {
            reasons.add("Production promotion requires verified restore drill evidence receipt")
        }

        return ProvenanceVerificationResult(
            isValid = reasons.isEmpty(),
            reasons = reasons,
        )
    }
}
