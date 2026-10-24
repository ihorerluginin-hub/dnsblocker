package com.biologigor.dnsblocker

/** Сборка исходящих IP+UDP пакетов для записи в TUN. */
object Packet {

    fun u16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    /** Собрать полный пакет: src/dst — 4 (IPv4) или 16 (IPv6) байт. */
    fun buildUdp(src: ByteArray, dst: ByteArray, sport: Int, dport: Int, payload: ByteArray): ByteArray {
        val isV6 = src.size == 16
        val ipLen = if (isV6) 40 else 20
        val udpLen = 8 + payload.size
        val out = ByteArray(ipLen + udpLen)

        if (!isV6) {
            out[0] = 0x45                      // версия 4, IHL 5
            out[2] = ((ipLen + udpLen) ushr 8).toByte()
            out[3] = (ipLen + udpLen).toByte()
            out[6] = 0x40                      // флаг DF
            out[8] = 64                        // TTL
            out[9] = 17                        // протокол UDP
            src.copyInto(out, 12)
            dst.copyInto(out, 16)
            val sum = onesComplement(out, 0, 20)
            out[10] = (sum ushr 8).toByte()
            out[11] = sum.toByte()
        } else {
            out[0] = 0x60                      // версия 6
            out[4] = (udpLen ushr 8).toByte()  // payload length
            out[5] = udpLen.toByte()
            out[6] = 17                        // next header = UDP
            out[7] = 64                        // hop limit
            src.copyInto(out, 8)
            dst.copyInto(out, 24)
        }

        val u = ipLen
        out[u] = (sport ushr 8).toByte()
        out[u + 1] = sport.toByte()
        out[u + 2] = (dport ushr 8).toByte()
        out[u + 3] = dport.toByte()
        out[u + 4] = (udpLen ushr 8).toByte()
        out[u + 5] = udpLen.toByte()
        payload.copyInto(out, u + 8)

        val cs = udpChecksum(out, u, udpLen, src, dst)
        out[u + 6] = (cs ushr 8).toByte()
        out[u + 7] = cs.toByte()
        return out
    }

    private fun onesComplement(b: ByteArray, from: Int, to: Int): Int {
        var sum = 0
        var i = from
        while (i + 1 < to) {
            sum += u16(b, i)
            i += 2
        }
        if (i < to) sum += (b[i].toInt() and 0xFF) shl 8
        return fold(sum)
    }

    private fun udpChecksum(b: ByteArray, udpOff: Int, udpLen: Int, src: ByteArray, dst: ByteArray): Int {
        var sum = 0
        var i = 0
        while (i < src.size) {
            sum += u16(src, i) + u16(dst, i)
            i += 2
        }
        sum += 17 + udpLen
        val end = udpOff + udpLen
        var j = udpOff
        while (j + 1 < end) {
            sum += u16(b, j)
            j += 2
        }
        if (j < end) sum += (b[j].toInt() and 0xFF) shl 8
        val cs = fold(sum)
        return if (cs == 0) 0xFFFF else cs
    }

    private fun fold(sum: Int): Int {
        var s = sum
        while (s ushr 16 != 0) s = (s and 0xFFFF) + (s ushr 16)
        return s.inv() and 0xFFFF
    }
}
