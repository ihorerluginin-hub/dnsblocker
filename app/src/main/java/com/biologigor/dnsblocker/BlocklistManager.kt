package com.biologigor.dnsblocker

import android.content.Context
import java.io.File
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * Хранение и разбор списков блокировки.
 * Формат: hosts ("0.0.0.0 домен"), простые домены в строку и
 * минимальная поддержка правил Adblock ("||домен^").
 * Опциональный whitelist: файл whitelist.txt в filesDir.
 */
object BlocklistManager {

    const val DEFAULT_LIST_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

    @Volatile private var blacklist: Set<String> = emptySet()
    @Volatile private var whitelist: Set<String> = emptySet()

    @Volatile
    var loaded = false
        private set

    val entryCount: Int get() = blacklist.size

    fun hasCustomList(context: Context): Boolean {
        val f = File(context.filesDir, "blocklist.txt")
        return f.isFile && f.length() > 0
    }

    fun isBlocked(name: String): Boolean {
        if (!loaded || name.isEmpty()) return false
        if (matches(name, whitelist)) return false
        return matches(name, blacklist)
    }

    /** Точное имя или любой родительский суффикс в списке — блок. */
    private fun matches(name: String, set: Set<String>): Boolean {
        var n = name
        while (true) {
            if (set.contains(n)) return true
            val dot = n.indexOf('.')
            if (dot <= 0) return false
            n = n.substring(dot + 1)
        }
    }

    fun ensureLoaded(context: Context) {
        if (loaded) return
        synchronized(this) {
            if (loaded) return
            blacklist = if (hasCustomList(context)) {
                parse(File(context.filesDir, "blocklist.txt").inputStream())
            } else {
                parse(context.assets.open("default_blocklist.txt"))
            }
            val wl = File(context.filesDir, "whitelist.txt")
            if (wl.isFile) whitelist = parse(wl.inputStream())
            loaded = true
        }
    }

    /**
     * Скачать список по URL, разобрать, сохранить в filesDir.
     * Вызывать из фонового потока.
     */
    fun updateFromUrl(
        context: Context,
        url: String,
        onProgress: (String) -> Unit,
        onDone: (ok: Boolean, message: String) -> Unit
    ) {
        try {
            ensureLoaded(context)
            val tmp = File(context.cacheDir, "blocklist.tmp")
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 15000
            conn.readTimeout = 60000
            conn.instanceFollowRedirects = true
            try {
                conn.inputStream.use { input ->
                    tmp.outputStream().use { output ->
                        val buf = ByteArray(16 * 1024)
                        var total = 0L
                        while (true) {
                            val n = input.read(buf)
                            if (n < 0) break
                            output.write(buf, 0, n)
                            total += n
                            if (total / (256 * 1024) != (total - n) / (256 * 1024)) {
                                onProgress("Скачано ${total / 1024} КБ…")
                            }
                        }
                    }
                }
            } finally {
                conn.disconnect()
            }
            val fresh = parse(tmp.inputStream())
            if (fresh.size < 1000) {
                tmp.delete()
                onDone(false, "В списке всего ${fresh.size} доменов — не сохраняю, проверьте URL")
                return
            }
            synchronized(this) {
                tmp.copyTo(File(context.filesDir, "blocklist.txt"), overwrite = true)
                blacklist = fresh
                loaded = true
            }
            tmp.delete()
            onDone(true, "Список обновлён: ${fresh.size} доменов")
        } catch (e: Exception) {
            onDone(false, "Ошибка обновления: ${e.message ?: e.javaClass.simpleName}")
        }
    }

    private fun parse(input: InputStream): HashSet<String> {
        val set = HashSet<String>(100_000)
        input.bufferedReader(Charsets.UTF_8).useLines { lines ->
            for (raw in lines) parseLine(raw, set)
        }
        return set
    }

    private val domainRegex = Regex("^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$")

    private fun parseLine(raw: String, out: MutableSet<String>) {
        var line = raw.trim()
        if (line.isEmpty()) return
        val hash = line.indexOf('#')
        if (hash >= 0) line = line.substring(0, hash).trim()
        if (line.isEmpty()) return
        if (line.startsWith("@@")) return  // adblock-белые списки не поддерживаем
        val d = if (line.startsWith("||")) extractAdblock(line) else extractHosts(line)
        if (d != null) out.add(d)
    }

    private fun extractAdblock(line: String): String? {
        var d = line.substring(2)
        val stop = d.indexOfFirst { it == '^' || it == '$' || it == '/' || it == '*' }
        if (stop >= 0) d = d.substring(0, stop)
        return cleanDomain(d)
    }

    private fun extractHosts(line: String): String? {
        val parts = line.split(Regex("\\s+"))
        return when {
            parts.size >= 2 -> {
                val ip = parts[0]
                if (ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::1" || ip == "::" || ip == "fe80::1%lo0") {
                    cleanDomain(parts[1])
                } else null
            }
            parts.size == 1 -> cleanDomain(parts[0])
            else -> null
        }
    }

    private fun cleanDomain(d0: String): String? {
        var d = d0.lowercase().trim().trimEnd('.')
        while (d.startsWith("*.")) d = d.substring(2)
        val slash = d.indexOf('/')
        if (slash >= 0) d = d.substring(0, slash)
        when (d) {
            "localhost", "localhost.localdomain", "local", "broadcasthost",
            "ip6-localhost", "ip6-loopback" -> return null
        }
        if (d.isEmpty() || d.length > 253) return null
        return if (domainRegex.matches(d)) d else null
    }
}
