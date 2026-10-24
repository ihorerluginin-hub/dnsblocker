package com.biologigor.dnsblocker

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.TextView
import kotlin.concurrent.thread

class MainActivity : Activity() {

    private lateinit var tvStatus: TextView
    private lateinit var btnToggle: Button
    private lateinit var tvStats: TextView
    private lateinit var btnUpdate: Button
    private lateinit var tvUpdate: TextView

    private val ui = Handler(Looper.getMainLooper())
    private val tick = object : Runnable {
        override fun run() {
            refresh()
            ui.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        tvStatus = findViewById(R.id.tvStatus)
        btnToggle = findViewById(R.id.btnToggle)
        tvStats = findViewById(R.id.tvStats)
        btnUpdate = findViewById(R.id.btnUpdate)
        tvUpdate = findViewById(R.id.tvUpdate)

        btnToggle.setOnClickListener {
            android.util.Log.w("DnsBlocker", "toggle pressed, running=${VpnTunnelService.isRunning}")
            if (VpnTunnelService.isRunning) {
                // stopService() на некоторых прошивках для foreground-VPN игнорируется,
                // поэтому команду «выключиться» отправляем сервису явно
                startService(
                    Intent(this, VpnTunnelService::class.java).setAction(VpnTunnelService.ACTION_STOP)
                )
            } else {
                val consent = VpnService.prepare(this)
                if (consent == null) startVpn() else startActivityForResult(consent, 1)
            }
        }

        btnUpdate.setOnClickListener { updateList() }

        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission("android.permission.POST_NOTIFICATIONS") != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 2)
        }

        // первый запуск: тянем полный список в фоне, пока работает встроенный
        if (!BlocklistManager.hasCustomList(this)) {
            thread(name = "first-update") {
                BlocklistManager.updateFromUrl(
                    applicationContext, BlocklistManager.DEFAULT_LIST_URL,
                    onProgress = { },
                    onDone = { ok, msg -> runOnUiThread { if (!ok) tvUpdate.text = msg } }
                )
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1) {
            if (resultCode == RESULT_OK) startVpn()
            else tvUpdate.text = "Доступ к VPN не выдан — без него блокировка не работает"
        }
    }

    private fun startVpn() {
        startForegroundService(Intent(this, VpnTunnelService::class.java))
    }

    private fun updateList() {
        btnUpdate.isEnabled = false
        tvUpdate.text = "Скачиваю…"
        thread(name = "update-list") {
            BlocklistManager.updateFromUrl(
                applicationContext, BlocklistManager.DEFAULT_LIST_URL,
                onProgress = { s -> runOnUiThread { tvUpdate.text = s } },
                onDone = { _, msg -> runOnUiThread { tvUpdate.text = msg; btnUpdate.isEnabled = true } }
            )
        }
    }

    private fun refresh() {
        val running = VpnTunnelService.isRunning
        tvStatus.text = if (running) "Работает" else "Остановлен"
        btnToggle.text = if (running) "Выключить" else "Включить"
        val sb = StringBuilder()
        sb.append("Запросов: ").append(VpnStats.queries.get()).append('\n')
        sb.append("Заблокировано: ").append(VpnStats.blocked.get()).append('\n')
        sb.append("Доменов в списке: ").append(BlocklistManager.entryCount)
        if (running && VpnStats.startedAt.get() > 0) {
            val sec = (System.currentTimeMillis() - VpnStats.startedAt.get()) / 1000
            sb.append('\n').append("Работает: ").append(formatDuration(sec))
        }
        tvStats.text = sb
    }

    private fun formatDuration(sec: Long): String {
        val h = sec / 3600
        val m = (sec % 3600) / 60
        val s = sec % 60
        return if (h > 0) "%d:%02d:%02d".format(h, m, s) else "%d:%02d".format(m, s)
    }

    override fun onResume() {
        super.onResume()
        refresh()
        ui.post(tick)
    }

    override fun onPause() {
        super.onPause()
        ui.removeCallbacks(tick)
    }
}
