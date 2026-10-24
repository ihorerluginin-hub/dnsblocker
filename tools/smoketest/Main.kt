import com.biologigor.dnsblocker.Dns
import com.biologigor.dnsblocker.Packet
import kotlin.system.exitProcess

var failures = 0
fun check(cond: Boolean, msg: String) {
    if (cond) println("OK   $msg") else { println("FAIL $msg"); failures++ }
}

fun fold(sum0: Int): Int {
    var s = sum0
    while (s ushr 16 != 0) s = (s and 0xFFFF) + (s ushr 16)
    return s
}

fun buildQuery(name: String, qtype: Int, id: Int = 0x1234): ByteArray {
    val labels = name.split('.')
    val out = ByteArray(12 + name.length + 2 + 4)
    out[0] = (id ushr 8).toByte(); out[1] = id.toByte()
    out[2] = 0x01; out[3] = 0x00   // RD=1
    out[5] = 1                      // QDCOUNT=1
    var off = 12
    for (l in labels) {
        out[off] = l.length.toByte(); off++
        for (c in l) { out[off] = c.code.toByte(); off++ }
    }
    out[off] = 0; off++
    out[off] = (qtype ushr 8).toByte(); out[off + 1] = qtype.toByte(); off += 2
    out[off] = 0; out[off + 1] = 1  // IN
    return out
}

// независимая проверка UDP-чексуммы: пересуммировать с включённым полем cs → 0 после дополнения
fun udpChecksumValid(p: ByteArray, udpOff: Int, udpLen: Int, src: ByteArray, dst: ByteArray): Boolean {
    var sum = 0
    var i = 0
    while (i < src.size) {
        sum += Packet.u16(src, i) + Packet.u16(dst, i)
        i += 2
    }
    sum += 17 + udpLen
    val end = udpOff + udpLen
    var j = udpOff
    while (j + 1 < end) { sum += Packet.u16(p, j); j += 2 }
    if (j < end) sum += (p[j].toInt() and 0xFF) shl 8
    return (fold(sum).inv() and 0xFFFF) == 0
}

fun main() {
    // 1. разбор запроса со смешанным регистром
    val q = buildQuery("Ads.Example.COM", Dns.TYPE_A, 0x1234)
    val parsed = Dns.parseQuery(q)
    check(parsed != null, "query parsed")
    if (parsed == null) exitProcess(1)
    check(parsed.id == 0x1234, "id")
    check(parsed.name == "ads.example.com", "name lowercase, got: ${parsed.name}")
    check(parsed.type == Dns.TYPE_A, "type A")
    check(parsed.qEnd == q.size, "qEnd == payload size (${parsed.qEnd})")
    check((parsed.flags and 0x0100) != 0, "RD flag seen")

    // 2. ответ не должен парситься как запрос
    check(Dns.parseQuery(Dns.buildResponse(parsed, true)) == null, "response rejected by parseQuery")

    // 3. sinkhole A
    val respA = Dns.buildResponse(parsed, blocked = true)
    check(respA.size == q.size + 16, "A response size")
    val rflags = ((respA[2].toInt() and 0xFF) shl 8) or (respA[3].toInt() and 0xFF)
    check(rflags == 0x8180, "flags QR|RD|RA|NOERROR, got ${Integer.toHexString(rflags)}")
    check(respA[4].toInt() == 0 && respA[5].toInt() == 1, "qdcount 1")
    check(respA[6].toInt() == 0 && respA[7].toInt() == 1, "ancount 1")
    check(
        respA.copyOfRange(12, parsed.qEnd).contentEquals(q.copyOfRange(12, parsed.qEnd)),
        "question section copied"
    )
    val a = parsed.qEnd
    check(respA[a] == 0xC0.toByte() && respA[a + 1] == 0x0C.toByte(), "answer name pointer")
    check(respA[a + 2].toInt() == 0 && respA[a + 3].toInt() == 1, "answer type A")
    check(respA[a + 4].toInt() == 0 && respA[a + 5].toInt() == 1, "class IN")
    check(respA[a + 9].toInt() == 60, "TTL 60")
    check(respA[a + 10].toInt() == 0 && respA[a + 11].toInt() == 4, "rdlength 4")
    check(respA.sliceArray(a + 12 until a + 16).all { it == 0.toByte() }, "rdata 0.0.0.0")

    // 4. sinkhole AAAA
    val q6 = buildQuery("ads.example.com", Dns.TYPE_AAAA)
    val r6 = Dns.buildResponse(Dns.parseQuery(q6)!!, true)
    check(r6.size == q6.size + 28, "AAAA response size")
    check(r6[a + 11].toInt() == 16, "AAAA rdlength 16")
    check(r6.sliceArray(a + 12 until a + 28).all { it == 0.toByte() }, "rdata ::")

    // 5. заблокированный не-A тип → NXDOMAIN без ответов
    val qTxt = buildQuery("ads.example.com", 16)
    val rTxt = Dns.buildResponse(Dns.parseQuery(qTxt)!!, true)
    check(rTxt.size == qTxt.size, "TXT response has no answer section")
    check((rTxt[3].toInt() and 0x0F) == 3, "rcode NXDOMAIN")
    check(rTxt[6].toInt() == 0 && rTxt[7].toInt() == 0, "ancount 0")

    // 6. SERVFAIL (апстрим не ответил)
    val rFail = Dns.buildResponse(parsed, blocked = false)
    check((rFail[3].toInt() and 0x0F) == 2, "rcode SERVFAIL")

    // 7. мусор отбрасывается
    check(Dns.parseQuery(ByteArray(10)) == null, "too short rejected")
    val withQr = buildQuery("a.b", 1); withQr[2] = 0x80.toByte()
    check(Dns.parseQuery(withQr) == null, "response (QR=1) rejected")
    val twoQ = buildQuery("a.b", 1); twoQ[5] = 2
    check(Dns.parseQuery(twoQ) == null, "qdcount=2 rejected")

    // 8. IPv4 + UDP, нечётная длина пейлоада
    val src = byteArrayOf(10, 111, 222.toByte(), 3)
    val dst = byteArrayOf(192.toByte(), 168.toByte(), 1, 55)
    val payload = ByteArray(37) { (it * 7 + 3).toByte() }
    val pkt = Packet.buildUdp(src, dst, 53, 41234, payload)
    check(pkt.size == 20 + 8 + 37, "v4 packet size")
    check(pkt[0] == 0x45.toByte(), "version 4 / ihl 5")
    check(pkt[8] == 64.toByte() && pkt[9] == 17.toByte(), "ttl 64 / proto udp")
    check(pkt.copyOfRange(12, 16).contentEquals(src), "v4 src")
    check(pkt.copyOfRange(16, 20).contentEquals(dst), "v4 dst")
    check(Packet.u16(pkt, 2) == pkt.size, "v4 total length")
    var s = 0; var i = 0
    while (i < 20) { s += Packet.u16(pkt, i); i += 2 }
    check((fold(s).inv() and 0xFFFF) == 0, "v4 header checksum valid")
    check(Packet.u16(pkt, 20) == 53 && Packet.u16(pkt, 22) == 41234, "udp ports")
    check(Packet.u16(pkt, 24) == 45, "udp length")
    check(udpChecksumValid(pkt, 20, 45, src, dst), "udp checksum valid (odd payload)")
    check(pkt.copyOfRange(28, pkt.size).contentEquals(payload), "udp payload intact")

    // 9. IPv6 + UDP
    val src6 = ByteArray(16) { (it + 1).toByte() }
    val dst6 = ByteArray(16) { (it + 2).toByte() }
    val pkt6 = Packet.buildUdp(src6, dst6, 53, 5353, payload)
    check(pkt6.size == 40 + 8 + 37, "v6 packet size")
    check(pkt6[0] == 0x60.toByte(), "v6 version")
    check(Packet.u16(pkt6, 4) == 45, "v6 payload length")
    check(pkt6[6] == 17.toByte(), "v6 next header udp")
    check(pkt6[7] == 64.toByte(), "v6 hop limit")
    check(pkt6.copyOfRange(8, 24).contentEquals(src6), "v6 src")
    check(pkt6.copyOfRange(24, 40).contentEquals(dst6), "v6 dst")
    check(udpChecksumValid(pkt6, 40, 45, src6, dst6), "v6 udp checksum valid")

    // 10. чётная длина пейлоада тоже валидна
    val even = ByteArray(36) { (it * 3 + 1).toByte() }
    val pktEven = Packet.buildUdp(src, dst, 53, 1234, even)
    check(udpChecksumValid(pktEven, 20, 44, src, dst), "udp checksum valid (even payload)")

    println()
    println(if (failures == 0) "ALL PASSED" else "FAILURES: $failures")
    if (failures > 0) exitProcess(1)
}
