package com.biologigor.dnsblocker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

object VpnStats {
    val startedAt = AtomicLong(0)
    val queries = AtomicLong(0)
    val blocked = AtomicLong(0)
}

/**
 * VPN без root, перехватывающий только DNS.
 *
 * В туннель заводится фейковый DNS-сервер (он же DNS сервер VPN-интерфейса) и
 * горстка публичных DNS, куда приложения любят писать адреса напрямую.
 * Всё остальное мимо туннеля: трафик не проксируется, батарея не тратится.
 * Из туннеля берём только UDP/53: A/AAAA по блок-листу — пустой ответ,
 * остальное — прозрачная пересылка на обычный DNS сети через защищённый сокет.
 */
class VpnTunnelService : VpnService() {

    companion object {
        // адрес интерфейса и адрес DNS-сервера ОБЯЗАНЫ различаться:
        // запросы на адрес самого TUN ядро доставляет локально (loopback),
        // и в туннель они не попадают никогда
        private const val VPN_ADDR_V4 = "10.111.222.3"
        private const val VPN_ADDR_V6 = "fdae:b1d7:6c61::3"
        private const val VPN_DNS_V4 = "10.111.222.4"
        private const val VPN_DNS_V6 = "fdae:b1d7:6c61::4"

        // публичные DNS, в которые некоторые приложения пишут адреса напрямую:
        // их тоже заводим в туннель, иначе они обходили бы фильтр
        private val KNOWN_DNS_V4 = listOf(
            "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
            "208.67.222.222", "208.67.220.220", "77.88.8.8", "77.88.8.1",
            "4.2.2.1", "4.2.2.2"
        )
        private val KNOWN_DNS_V6 = listOf(
            "2606:4700:4700::1111", "2606:4700:4700::1001",
            "2001:4860:4860::8888", "2001:4860:4860::8844",
            "2620:fe::fe", "2620:fe::9",
            "2620:119:35::35", "2620:119:53::53",
            "2a02:6b8::fe", "2a02:6b8:0:1::fe"
        )

        private const val UPSTREAM_TIMEOUT_MS = 4000
        private const val CHANNEL_ID = "dns_blocker"
        private const val NOTIFICATION_ID = 1

        /** Явная команда «выключиться» — надёжнее, чем stopService():
         *  на части прошивок он для foreground-VPN-сервиса просто игнорируется. */
        const val ACTION_STOP = "com.biologigor.dnsblocker.STOP"

        @Volatile
        var isRunning = false
            private set
    }

    private var tunFd: ParcelFileDescriptor? = null
    private var outStream: FileOutputStream? = null
    private val writeLock = Any()
    private var readerThread: Thread? = null
    private var executor: ExecutorService? = null

    @Volatile
    private var upstreamServers: List<InetAddress> = emptyList()

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            android.util.Log.w("DnsBlocker", "stop requested via intent")
            stopTunnel()
            stopForeground(Service.STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        startForeground(NOTIFICATION_ID, buildNotification())
        if (!isRunning) {
            isRunning = true
            thread(name = "tunnel-start") {
                try {
                    startTunnel()
                } catch (e: Exception) {
                    android.util.Log.e("DnsBlocker", "tunnel start failed", e)
                    stopSelf()
                }
            }
        }
        return START_STICKY
    }

    private fun startTunnel() {
        BlocklistManager.ensureLoaded(applicationContext)

        val builder = Builder()
            .addAddress(VPN_ADDR_V4, 32)
            .addAddress(VPN_ADDR_V6, 128)
            .addDnsServer(VPN_DNS_V4)
            .addDnsServer(VPN_DNS_V6)
            .addRoute(VPN_DNS_V4, 32)
            .addRoute(VPN_DNS_V6, 128)
            .setMtu(1500)
            .setSession("Блокировщик рекламы")
        // fd туннеля обязан быть блокирующим: в non-blocking read() отдаёт 0
        // вместо ожидания пакета и цикл чтения сразу завершается
        builder.setBlocking(true)
        for (ip in KNOWN_DNS_V4) builder.addRoute(ip, 32)
        for (ip in KNOWN_DNS_V6) builder.addRoute(ip, 128)

        val fd = builder.establish()
            ?: throw IllegalStateException("establish() == null: согласие на VPN не выдано")

        upstreamServers = resolveUpstreams()

        tunFd = fd
        outStream = FileOutputStream(fd.fileDescriptor)
        executor = Executors.newFixedThreadPool(4)
        VpnStats.startedAt.set(System.currentTimeMillis())

        readerThread = thread(name = "tun-reader") { readLoop(fd) }
        android.util.Log.i("DnsBlocker", "tunnel up, upstreams: ${upstreamServers.joinToString { it.hostAddress ?: "?" }}")
    }

    /** DNS-серверы активной сети (не VPN), на крайний случай — Cloudflare и Google. */
    private fun resolveUpstreams(): List<InetAddress> {
        val result = ArrayList<InetAddress>()
        try {
            val cm = getSystemService(ConnectivityManager::class.java)
            for (net in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(net) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                val lp = cm.getLinkProperties(net) ?: continue
                for (dns in lp.dnsServers) {
                    val host = dns.hostAddress ?: continue
                    if (host == VPN_DNS_V4 || host == VPN_DNS_V6) continue
                    if (!result.contains(dns)) result.add(dns)
                }
            }
        } catch (_: Exception) {
        }
        if (result.isEmpty()) {
            // литеральные адреса — обращения к DNS не будет, зацикливание невозможно
            result.add(InetAddress.getByName("1.1.1.1"))
            result.add(InetAddress.getByName("8.8.8.8"))
        }
        return result
    }

    private fun readLoop(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val buf = ByteArray(65536)
        android.util.Log.i("DnsBlocker", "readLoop started")
        while (isRunning) {
            val n = try {
                input.read(buf)
            } catch (e: Exception) {
                android.util.Log.w("DnsBlocker", "readLoop read failed: $e")
                break
            }
            if (n <= 0) {
                android.util.Log.w("DnsBlocker", "readLoop read $n, exiting")
                break
            }
            try {
                handlePacket(buf, n)
            } catch (e: Exception) {
                android.util.Log.w("DnsBlocker", "handlePacket failed", e)
                // битый пакет не должен ронять цикл
            }
        }
        try { input.close() } catch (_: Exception) {}
    }

    private fun handlePacket(b: ByteArray, len: Int) {
        when (b[0].toInt() ushr 4) {
            4 -> handleV4(b, len)
            6 -> handleV6(b, len)
        }
    }

    private fun handleV4(b: ByteArray, len: Int) {
        if (len < 20) return
        val ihl = (b[0].toInt() and 0x0F) * 4
        if (ihl < 20 || len < ihl + 8) return
        if ((b[9].toInt() and 0xFF) != 17) return  // только UDP; TCP (DoT) сюда не попадает
        handleUdp(b, len, ihl, b.copyOfRange(12, 16), b.copyOfRange(16, 20))
    }

    private fun handleV6(b: ByteArray, len: Int) {
        if (len < 48) return
        var next = b[6].toInt() and 0xFF
        var off = 40
        while (next == 0 || next == 43 || next == 60 || next == 51) { // hop-by-hop, routing, dest opts, AH
            if (off + 8 > len) return
            next = b[off].toInt() and 0xFF
            off += 8 + (b[off + 1].toInt() and 0xFF) * 8
        }
        if (next != 17 || off + 8 > len) return
        handleUdp(b, len, off, b.copyOfRange(8, 24), b.copyOfRange(24, 40))
    }

    private fun handleUdp(b: ByteArray, len: Int, us: Int, src: ByteArray, dst: ByteArray) {
        val dport = Packet.u16(b, us + 2)
        if (dport != 53) return
        val sport = Packet.u16(b, us)
        val udpLen = Packet.u16(b, us + 4)
        val dnsLen = if (udpLen in 8..(len - us)) udpLen - 8 else len - us - 8
        if (dnsLen <= 0) return
        val dnsPayload = b.copyOfRange(us + 8, us + 8 + dnsLen)

        VpnStats.queries.incrementAndGet()

        val q = Dns.parseQuery(dnsPayload)
        if (q != null && BlocklistManager.isBlocked(q.name)) {
            VpnStats.blocked.incrementAndGet()
            writePacket(dst, src, 53, sport, Dns.buildResponse(q, blocked = true))
        } else {
            val ex = executor ?: return
            try {
                ex.execute { forward(dnsPayload, dst, src, sport) }
            } catch (_: RejectedExecutionException) {
            }
        }
    }

    private fun forward(dnsPayload: ByteArray, origDst: ByteArray, origSrc: ByteArray, clientPort: Int) {
        val response = queryUpstream(dnsPayload)
        if (response != null) {
            android.util.Log.d("DnsBlocker", "forward ok, ${response.size} bytes")
            writePacket(origDst, origSrc, 53, clientPort, response)
        } else {
            android.util.Log.w("DnsBlocker", "forward failed, sending SERVFAIL")
            val q = Dns.parseQuery(dnsPayload)
            if (q != null) writePacket(origDst, origSrc, 53, clientPort, Dns.buildResponse(q, blocked = false))
        }
    }

    /** Отправить запрос на апстримы по очереди, вернуть первый корректный ответ. */
    private fun queryUpstream(payload: ByteArray): ByteArray? {
        val servers = upstreamServers
        for (addr in servers) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                if (!protect(socket)) {
                    android.util.Log.w("DnsBlocker", "protect(${addr.hostAddress}) == false")
                    continue
                }
                socket.soTimeout = UPSTREAM_TIMEOUT_MS
                socket.send(DatagramPacket(payload, payload.size, addr, 53))
                val buf = ByteArray(8192)
                val pkt = DatagramPacket(buf, buf.size)
                socket.receive(pkt)
                val n = pkt.length
                if (n < 12) continue
                if ((buf[2].toInt() and 0x80) == 0) continue                   // не ответ
                if (buf[0] != payload[0] || buf[1] != payload[1]) continue     // чужой id
                return buf.copyOfRange(0, n)
            } catch (e: Exception) {
                android.util.Log.w("DnsBlocker", "upstream ${addr.hostAddress} failed: $e")
            } finally {
                try { socket?.close() } catch (_: Exception) {}
            }
        }
        return null
    }

    private fun writePacket(srcIp: ByteArray, dstIp: ByteArray, sport: Int, dport: Int, payload: ByteArray) {
        val packet = Packet.buildUdp(srcIp, dstIp, sport, dport, payload)
        synchronized(writeLock) {
            val os = outStream ?: return
            try {
                os.write(packet)
                os.flush()
            } catch (_: Exception) {
            }
        }
    }

    private fun stopTunnel() {
        isRunning = false
        executor?.shutdownNow()
        executor = null
        try { tunFd?.close() } catch (_: Exception) {}
        tunFd = null
        synchronized(writeLock) { outStream = null }
        VpnStats.startedAt.set(0)
        readerThread?.interrupt()
        readerThread = null
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopTunnel()
        stopSelf()
        super.onRevoke()
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, getString(R.string.notif_channel_name), NotificationManager.IMPORTANCE_LOW)
            )
        }
    }

    private fun buildNotification(): Notification {
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val b = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return b.setContentTitle(getString(R.string.notif_title))
            .setContentText(getString(R.string.notif_text))
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }
}
