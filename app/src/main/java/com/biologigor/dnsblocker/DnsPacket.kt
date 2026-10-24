package com.biologigor.dnsblocker

/** Разбор DNS-запросов и сборка ответов (без библиотек, минимум аллокаций). */
object Dns {

    const val TYPE_A = 1
    const val TYPE_AAAA = 28

    class Query(
        val id: Int,
        val flags: Int,
        val name: String,        // в нижнем регистре, без завершающей точки
        val type: Int,
        val qEnd: Int,           // смещение сразу за секцией Question в payload
        val payload: ByteArray   // оригинальный DNS-пейлоад целиком
    )

    /** Вернуть null, если это не одиночный вопрос, который мы умеем разобрать. */
    fun parseQuery(p: ByteArray): Query? {
        if (p.size < 12 + 5) return null          // 12 байт заголовка + минимальный вопрос
        val flags = Packet.u16(p, 2)
        if ((flags and 0x8000) != 0) return null  // это ответ, не запрос
        if (Packet.u16(p, 4) != 1) return null    // ждём ровно один вопрос
        var off = 12
        val sb = StringBuilder(64)
        while (true) {
            if (off >= p.size) return null
            val len = p[off].toInt() and 0xFF
            if (len == 0) { off++; break }
            if ((len and 0xC0) != 0) return null  // сжатие в Question не бывает
            if (off + 1 + len > p.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 1..len) {
                val c = p[off + i].toInt() and 0xFF
                if (c == 46) return null          // точка внутри метки — мусор
                sb.append(c.toChar())
            }
            off += 1 + len
            if (sb.length > 253) return null
        }
        if (off + 4 > p.size) return null
        val type = Packet.u16(p, off)
        return Query(Packet.u16(p, 0), flags, sb.toString().lowercase(), type, off + 4, p)
    }

    /**
     * Собрать DNS-ответ на запрос q.
     * blocked = true: для A/AAAA — NOERROR с пустым адресом (0.0.0.0 / ::),
     *                 для остальных типов — NXDOMAIN.
     * blocked = false: SERVFAIL (используется, когда ни один апстрим не ответил).
     */
    fun buildResponse(q: Query, blocked: Boolean): ByteArray {
        val sinkhole: Int? = when {
            !blocked -> null
            q.type == TYPE_A -> TYPE_A
            q.type == TYPE_AAAA -> TYPE_AAAA
            else -> null
        }
        val rcode = when {
            sinkhole != null -> 0          // NOERROR
            blocked -> 3                   // NXDOMAIN
            else -> 2                      // SERVFAIL
        }
        val answerLen = when (sinkhole) {
            TYPE_A -> 16                   // указатель(2)+тип(2)+класс(2)+TTL(4)+rdlen(2)+rdata(4)
            TYPE_AAAA -> 28                // то же, но rdata 16 байт
            else -> 0
        }
        val total = q.qEnd + answerLen
        val out = ByteArray(total)
        out[0] = (q.id ushr 8).toByte()
        out[1] = q.id.toByte()
        val flags = 0x8000 or (q.flags and 0x0100) or 0x0080 or rcode  // QR, RD(из запроса), RA, rcode
        out[2] = (flags ushr 8).toByte()
        out[3] = flags.toByte()
        out[5] = 1                         // QDCOUNT = 1
        out[7] = if (answerLen > 0) 1 else 0  // ANCOUNT
        System.arraycopy(q.payload, 12, out, 12, q.qEnd - 12)
        if (sinkhole != null) {
            val off = q.qEnd
            out[off] = 0xC0.toByte()
            out[off + 1] = 0x0C            // указатель на имя из Question (смещение 12)
            out[off + 2] = (sinkhole ushr 8).toByte()
            out[off + 3] = sinkhole.toByte()
            out[off + 4] = 0
            out[off + 5] = 1               // класс IN
            out[off + 9] = 60              // TTL = 60 секунд
            out[off + 11] = (if (sinkhole == TYPE_A) 4 else 16).toByte()
            // RDATA уже нули: 0.0.0.0 для A, :: для AAAA
        }
        return out
    }
}
