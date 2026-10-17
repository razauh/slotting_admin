package com.slotting.admin.upload

object UploadMimeSniffer {
    fun normalize(value: String): String = value.substringBefore(';').trim().lowercase()

    fun sniff(bytes: ByteArray): String? {
        if (bytes.isEmpty()) return null
        if (bytes.startsWith(byteArrayOf(0x7F, 0x45, 0x4C, 0x46)) ||
            bytes.startsWith(byteArrayOf(0x4D, 0x5A)) ||
            bytes.startsWith(byteArrayOf(0x50, 0x4B, 0x03, 0x04))) return null
        if (bytes.startsWith(byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte()))) return "image/jpeg"
        if (bytes.startsWith(byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A))) return "image/png"
        if (bytes.startsWith("%PDF-".toByteArray(Charsets.US_ASCII))) return "application/pdf"
        if (bytes.size >= 12 && bytes.copyOfRange(0, 4).toString(Charsets.US_ASCII) == "RIFF" &&
            bytes.copyOfRange(8, 12).toString(Charsets.US_ASCII) == "WEBP") return "image/webp"
        val text = bytes.toString(Charsets.UTF_8)
        if (text.any { it == '\u0000' || it.code < 0x09 || it.code in 0x0E..0x1F }) return null
        val trimmed = text.trim()
        if (trimmed.startsWith('{') || trimmed.startsWith('[')) return "application/json"
        if (trimmed.isNotEmpty() && trimmed.contains(',') && !trimmed.contains('<')) return "text/csv"
        if (trimmed.isNotEmpty() && !trimmed.contains('<') && !trimmed.contains('>')) return "text/plain"
        return null
    }

    private fun ByteArray.startsWith(prefix: ByteArray): Boolean =
        size >= prefix.size && prefix.indices.all { this[it] == prefix[it] }
}
