package dev.omega.vpn

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

class MainActivity : ComponentActivity() {
    private fun connect(link: String) {
        VpnRuntime.report(VpnRuntime.State.CONNECTING,"Подключение…")
        startForegroundService(Intent(this,OmegaVpnService::class.java)
            .setAction(OmegaVpnService.CONNECT).putExtra(OmegaVpnService.PROFILE,link))
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            var link by remember { mutableStateOf("") }
            var error by remember { mutableStateOf("") }
            val permission = rememberLauncherForActivityResult(
                ActivityResultContracts.StartActivityForResult()
            ) { result ->
                if (result.resultCode == RESULT_OK && link.isNotBlank()) connect(link)
                else VpnRuntime.report(VpnRuntime.State.DISCONNECTED,"VPN-разрешение не предоставлено")
            }
            OmegaScreen(
                link = link,
                onLink = { link = it; error = "" },
                error = error,
                onConnect = {
                    try {
                        VlessProfile.parse(link)
                        val request = VpnService.prepare(this)
                        if (request == null) connect(link) else permission.launch(request)
                    } catch (e: IllegalArgumentException) {
                        error = e.message ?: "Неверная ссылка"
                    }
                },
                onDisconnect = {
                    startService(Intent(this,OmegaVpnService::class.java)
                        .setAction(OmegaVpnService.DISCONNECT))
                })
        }
    }
}

@Composable
fun OmegaScreen(
    link: String, onLink: (String) -> Unit, error: String,
    onConnect: () -> Unit, onDisconnect: () -> Unit
) {
    val state = VpnRuntime.state
    MaterialTheme {
        Surface(color=Color(0xFF101627),modifier=Modifier.fillMaxSize()) {
            Column(Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement=Arrangement.Center,
                horizontalAlignment=Alignment.CenterHorizontally) {
                Text("Ω VPN",fontSize=37.sp,fontWeight=FontWeight.Bold,color=Color(0xFF8CBFFF))
                Spacer(Modifier.height(16.dp))
                Text(VpnRuntime.message,color=Color.White,textAlign=TextAlign.Center)
                Spacer(Modifier.height(28.dp))
                OutlinedTextField(
                    value=link,onValueChange=onLink,
                    label={Text("Вставьте VLESS / Reality")},singleLine=false,
                    minLines=2,maxLines=4,
                    visualTransformation=PasswordVisualTransformation(),
                    modifier=Modifier.fillMaxWidth())
                if (error.isNotEmpty()) Text(error,color=Color(0xFFFF9999))
                Spacer(Modifier.height(20.dp))
                if (state == VpnRuntime.State.CONNECTING || state == VpnRuntime.State.CORE_STARTED) {
                    Button(onClick=onDisconnect,modifier=Modifier.fillMaxWidth()) {
                        Text("Отключить")
                    }
                } else {
                    Button(onClick=onConnect,enabled=link.isNotBlank(),
                        modifier=Modifier.fillMaxWidth()) { Text("Подключить") }
                }
                Spacer(Modifier.height(24.dp))
                Text(
                    "M2 • Экспериментальная сборка. Ядро запущено ≠ интернет работает. " +
                    "Перед использованием нужны тесты смены IP, DNS, IPv6 и мобильной сети.",
                    color=Color(0xFF9CB0CB),fontSize=13.sp,textAlign=TextAlign.Center)
            }
        }
    }
}
