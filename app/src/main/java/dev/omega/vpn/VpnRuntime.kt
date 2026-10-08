package dev.omega.vpn

import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

/** UI-only state. Never expose or persist private profile data. */
object VpnRuntime {
    enum class State { DISCONNECTED, CONNECTING, CORE_STARTED, ERROR }
    var state by mutableStateOf(State.DISCONNECTED)
        private set
    var message by mutableStateOf("Не подключено")
        private set
    fun report(next: State, text: String) {
        Handler(Looper.getMainLooper()).post { state = next; message = text }
    }
}
