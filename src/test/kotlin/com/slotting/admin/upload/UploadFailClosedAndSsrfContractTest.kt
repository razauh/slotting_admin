package com.slotting.admin.upload

import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.kyc.DependencyFailureException
import com.slotting.admin.kyc.IdentityDocumentType
import com.slotting.admin.kyc.IdentityDocumentUploadCommand
import com.slotting.admin.kyc.IdentityDocumentUploadService
import com.slotting.admin.kyc.InvalidDocumentTypeException
import com.slotting.admin.observability.OutboundEndpointValidator
import com.slotting.admin.observability.ObservabilitySsrfException
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class UploadFailClosedAndSsrfContractTest {
    @Test
    fun defaultScannerConfigurationRejectsUploadFailClosed() {
        val service = IdentityDocumentUploadService()
        val error = assertThrows(DependencyFailureException::class.java) {
            service.uploadDocument(command(bytes = jpegBytes(), mimeType = "image/jpeg"))
        }
        assertEquals("DEPENDENCY_FAILURE", error.errorCode)
    }

    @Test
    fun magicByteMismatchRejectsDespiteAllowedDeclaredMime() {
        val service = IdentityDocumentUploadService(malwareScanner = CleanScanner)
        assertThrows(InvalidDocumentTypeException::class.java) {
            service.uploadDocument(command(bytes = jpegBytes(), mimeType = "application/pdf"))
        }
    }

    @Test
    fun executableBytesHaveNoAllowedSniffedType() {
        assertNull(UploadMimeSniffer.sniff(byteArrayOf(0x7F, 0x45, 0x4C, 0x46)))
    }

    @Test
    fun rfc1918AndAnyLocalUrlsAreRejected() {
        listOf("https://10.1.2.3", "https://172.16.2.3", "https://192.168.1.5", "https://0.0.0.0").forEach {
            assertThrows(ObservabilitySsrfException::class.java) {
                OutboundEndpointValidator.validateEndpoint(it)
            }
        }
    }

    @Test
    fun encodedIpSpellingsAreRejected() {
        listOf("http://2130706433", "http://0177.0.0.1", "http://0x7f000001").forEach {
            assertThrows(ObservabilitySsrfException::class.java) {
                OutboundEndpointValidator.validateEndpoint(it)
            }
        }
    }

    @Test
    fun blankUrlProducesExplicitVerdict() {
        assertThrows(ObservabilitySsrfException::class.java) {
            OutboundEndpointValidator.validateEndpoint(" ")
        }
    }

    private fun command(bytes: ByteArray, mimeType: String) = IdentityDocumentUploadCommand(
        principal = AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet()),
        tenantId = "tenant-1",
        userId = "player-1",
        documentType = IdentityDocumentType.PASSPORT,
        filename = "identity.jpg",
        mimeType = mimeType,
        fileBytes = bytes,
        idempotencyKey = "idempotency-1",
        correlationId = "correlation-1",
        causationId = "causation-1"
    )

    private fun jpegBytes() = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xE0.toByte(), 0x01)

    private object CleanScanner : com.slotting.admin.kyc.MalwareScannerPort {
        override fun scan(fileBytes: ByteArray, filename: String) =
            com.slotting.admin.kyc.MalwareScanOutcome(com.slotting.admin.kyc.MalwareScanStatus.CLEAN)
    }
}
