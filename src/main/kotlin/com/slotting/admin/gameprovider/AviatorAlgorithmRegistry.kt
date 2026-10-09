package com.slotting.admin.gameprovider

import java.math.BigDecimal

class UnsupportedAlgorithmException(
    val algorithmVersion: String,
) : FairnessAuthorityException(
    "UNSUPPORTED_ALGORITHM_VERSION",
    "Unsupported algorithm version $algorithmVersion",
)

object AviatorAlgorithmRegistry {
    const val VERSION_1_0_0 = "1.0.0"
    const val UNSUPPORTED_VERSION_FAILURE_CODE = "UNSUPPORTED_ALGORITHM_VERSION"

    private val implementations: Map<String, (String, String, String, String) -> BigDecimal> = mapOf(
        VERSION_1_0_0 to { serverSeed, clientSeed1, clientSeed2, clientSeed3 ->
            IndependentFairnessVerifier.calculateCrashMultiplier(serverSeed, clientSeed1, clientSeed2, clientSeed3)
        },
    )

    val supportedVersions: Set<String> = implementations.keys

    fun isSupported(algorithmVersion: String): Boolean = implementations.containsKey(algorithmVersion)

    fun requireSupported(algorithmVersion: String) {
        if (!isSupported(algorithmVersion)) {
            throw UnsupportedAlgorithmException(algorithmVersion)
        }
    }

    fun compute(
        algorithmVersion: String,
        serverSeed: String,
        clientSeed1: String,
        clientSeed2: String,
        clientSeed3: String,
    ): BigDecimal = implementations[algorithmVersion]?.invoke(serverSeed, clientSeed1, clientSeed2, clientSeed3)
        ?: throw UnsupportedAlgorithmException(algorithmVersion)
}
