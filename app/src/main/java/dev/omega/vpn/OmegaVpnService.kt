package dev.omega.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import libv2ray.CoreCallbackHandler
import libv2ray.CoreController
import libv2ray.Libv2ray
import java.util.concurrent.Executors

/** Native Xray TUN connector. Device-level network acceptance is still required. */
class OmegaVpnService : VpnService() {
    companion object {
        const val CONNECT = "dev.omega.vpn.CONNECT"
        const val DISCONNECT = "dev.omega.vpn.DISCONNECT"
        const val PROFILE = "vless_profile"
        private const val CHANNEL = "omega_tunnel"
        private const val NOTIFICATION_ID = 100
    }
    private val worker = Executors.newSingleThreadExecutor()
    private var controller: CoreController? = null
    private var tunnel: ParcelFileDescriptor? = null
    @Volatile private var running = false

    override fun onCreate() {
        super.onCreate()
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).createNotificationChannel(
            NotificationChannel(CHANNEL,"Статус Ω VPN",NotificationManager.IMPORTANCE_LOW))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == DISCONNECT || intent == null) {
            stopSelf()
            return START_NOT_STICKY
        }
        if (intent.action != CONNECT || running) return START_NOT_STICKY
        foreground()
        running = true
        val link = intent.getStringExtra(PROFILE)
        intent.removeExtra(PROFILE)
        worker.execute { startTunnel(link) }
        return START_NOT_STICKY
    }

    private fun foreground() {
        val pending = PendingIntent.getService(this,0,Intent(this,OmegaVpnService::class.java)
            .setAction(DISCONNECT),PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val notification = NotificationCompat.Builder(this,CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("Ω VPN")
            .setContentText("Подготовка туннеля")
            .setOngoing(true)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel,"Отключить",pending)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID,notification,ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else startForeground(NOTIFICATION_ID,notification)
    }

    private fun startTunnel(link: String?) {
        try {
            VpnRuntime.report(VpnRuntime.State.CONNECTING,"Подготовка VPN…")
            val p = VlessProfile.parse(link ?: "")
            if (prepare(this) != null) error("VPN permission revoked")
            val fd = Builder().setSession("Ω VPN").setMtu(1500)
                .addAddress("172.20.10.2",30).addRoute("0.0.0.0",0)
                .addDnsServer("1.1.1.1")
                .addAddress("fd00:1111:2222::2",126).addRoute("::",0)
                .apply { addDisallowedApplication(packageName) }
                .establish() ?: error("Android TUN unavailable")
            tunnel = fd
            Libv2ray.initCoreEnv(filesDir.absolutePath,"")
            val native = Libv2ray.newCoreController(object: CoreCallbackHandler {
                override fun startup(): Long {
                    VpnRuntime.report(VpnRuntime.State.CORE_STARTED,
                        "Xray запущен. Проверка IP/DNS обязательна")
                    return 0
                }
                override fun shutdown(): Long {
                    VpnRuntime.report(VpnRuntime.State.DISCONNECTED,"Отключено")
                    return 0
                }
                override fun onEmitStatus(code: Long, message: String?): Long = 0
            })
            controller = native
            // Go gomobile binding requires int (not long).
            native.startLoop(XrayConfigFactory.build(p),fd.fd)
        } catch (_: Throwable) {
            VpnRuntime.report(VpnRuntime.State.ERROR,"Ошибка запуска VPN. Проверьте ключ или сеть")
            stopSelf()
        }
    }

    private fun teardown() {
        try { controller?.stopLoop() } catch (_: Exception) { }
        controller = null
        try { tunnel?.close() } catch (_: Exception) { }
        tunnel = null
        running = false
        VpnRuntime.report(VpnRuntime.State.DISCONNECTED,"Не подключено")
    }

    override fun onRevoke() { stopSelf() }
    override fun onDestroy() {
        // Ordered behind startTunnel on the same worker, avoids close/use race.
        worker.execute { teardown() }
        worker.shutdown()
        super.onDestroy()
    }
}
