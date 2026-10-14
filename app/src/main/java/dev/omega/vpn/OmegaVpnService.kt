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

/**
 * Android TUN must close immediately on disconnect.
 *
 * The native startLoop() may block until stopLoop() returns; queuing stop on its
 * single-thread executor would deadlock the VPN teardown. No direct/cleartext
 * fallback is installed.
 */
class OmegaVpnService : VpnService() {
    companion object {
        const val CONNECT = "dev.omega.vpn.CONNECT"
        const val DISCONNECT = "dev.omega.vpn.DISCONNECT"
        const val PROFILE = "vless_profile"
        private const val CHANNEL = "omega_tunnel"
        private const val NOTIFICATION_ID = 100
    }

    private val worker = Executors.newSingleThreadExecutor()
    private val lifecycleLock = Any()
    private var controller: CoreController? = null
    private var tunnel: ParcelFileDescriptor? = null
    @Volatile private var stopping = false
    @Volatile private var running = false

    override fun onCreate() {
        super.onCreate()
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).createNotificationChannel(
            NotificationChannel(CHANNEL,"Статус Ω VPN",NotificationManager.IMPORTANCE_LOW))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null || intent.action == DISCONNECT) {
            disconnectNow()
            stopSelf()
            return START_NOT_STICKY
        }
        if (intent.action != CONNECT || running || stopping) return START_NOT_STICKY
        foreground()
        running = true
        val link = intent.getStringExtra(PROFILE)
        intent.removeExtra(PROFILE)
        worker.execute { startTunnel(link) }
        return START_NOT_STICKY
    }

    private fun foreground() {
        val pending = PendingIntent.getService(this, 0, Intent(this, OmegaVpnService::class.java)
            .setAction(DISCONNECT), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val notification = NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("Ω VPN")
            .setContentText("Подготовка туннеля")
            .setOngoing(true)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Отключить", pending)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID,notification,ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else startForeground(NOTIFICATION_ID,notification)
    }

    private fun startTunnel(link: String?) {
        var unownedFd: ParcelFileDescriptor? = null
        try {
            if (stopping) return
            VpnRuntime.report(VpnRuntime.State.CONNECTING,"Подготовка VPN…")
            val profile = VlessProfile.parse(link ?: "")
            if (prepare(this) != null) error("VPN permission revoked")
            if (stopping) return

            val fd = Builder().setSession("Ω VPN").setMtu(1500)
                .addAddress("172.20.10.2",30).addRoute("0.0.0.0",0)
                .addDnsServer("1.1.1.1")
                .addAddress("fd00:1111:2222::2",126).addRoute("::",0)
                .apply { addDisallowedApplication(packageName) }
                .establish() ?: error("Android TUN unavailable")
            unownedFd = fd
            synchronized(lifecycleLock) {
                if (stopping) return
                tunnel = fd
                unownedFd = null
            }

            if (stopping) return
            Libv2ray.initCoreEnv(filesDir.absolutePath,"")
            val native = Libv2ray.newCoreController(object: CoreCallbackHandler {
                override fun startup(): Long {
                    if (!stopping) {
                        VpnRuntime.report(VpnRuntime.State.CORE_STARTED,
                            "Xray запущен. Проверка IP/DNS обязательна")
                    }
                    return 0
                }
                override fun shutdown(): Long = 0
                override fun onEmitStatus(code: Long, message: String?): Long = 0
            })
            synchronized(lifecycleLock) {
                if (stopping) {
                    // The service was disconnected while JNI initialized.
                    // No startLoop() can be invoked after cancellation.
                    return
                }
                controller = native
            }
            if (stopping) return
            native.startLoop(XrayConfigFactory.build(profile),fd.fd)
            if (!stopping) error("Native Xray loop exited unexpectedly")
        } catch (_: Throwable) {
            if (!stopping) {
                VpnRuntime.report(VpnRuntime.State.ERROR,
                    "Ошибка VPN-туннеля. Проверьте сервер или соединение")
                disconnectNow(reportDisconnected = false)
                stopSelf()
            }
        } finally {
            // If cancelled in the window between TUN establishment and ownership,
            // the descriptor must never leak.
            try { unownedFd?.close() } catch (_: Exception) {}
        }
    }

    /**
     * Close the TUN on the caller (Android service) thread immediately.
     * Never wait for native startLoop() to return before closing Android's
     * file descriptor: that loop can be precisely what prevents worker progress.
     */
    private fun disconnectNow(reportDisconnected: Boolean = true) {
        val fd: ParcelFileDescriptor?
        val native: CoreController?
        synchronized(lifecycleLock) {
            stopping = true
            fd = tunnel
            tunnel = null
            native = controller
            controller = null
            running = false
        }
        try { fd?.close() } catch (_: Exception) {}
        if (native != null) {
            Thread({
                try { native.stopLoop() } catch (_: Throwable) {}
            }, "omega-native-stop").start()
        }
        if (reportDisconnected) {
            VpnRuntime.report(VpnRuntime.State.DISCONNECTED,"VPN отключён")
        }
    }

    override fun onRevoke() {
        disconnectNow(reportDisconnected = false)
        VpnRuntime.report(VpnRuntime.State.ERROR,"Android отозвал разрешение VPN")
        stopSelf()
    }

    override fun onDestroy() {
        // Do not queue disconnect behind blocking startLoop().
        disconnectNow()
        worker.shutdownNow()
        super.onDestroy()
    }
}
