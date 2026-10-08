package dev.omega.vpn

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private fun connect(link: String) {
        try {
            VpnRuntime.report(VpnRuntime.State.CONNECTING, "Подключение…")
            startForegroundService(Intent(this, OmegaVpnService::class.java)
                .setAction(OmegaVpnService.CONNECT)
                .putExtra(OmegaVpnService.PROFILE, link))
        } catch (_: Exception) {
            VpnRuntime.report(VpnRuntime.State.ERROR, "Не удалось запустить VPN-сервис")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            var nodes by remember { mutableStateOf<List<PublicNode>>(emptyList()) }
            var position by remember { mutableIntStateOf(0) }
            var pendingLink by remember { mutableStateOf<String?>(null) }
            var loading by remember { mutableStateOf(false) }
            var riskAcknowledged by remember { mutableStateOf(false) }
            var error by remember { mutableStateOf("") }
            val scope = rememberCoroutineScope()

            val permission = rememberLauncherForActivityResult(
                ActivityResultContracts.StartActivityForResult()
            ) { result ->
                val chosen = pendingLink
                pendingLink = null
                if (result.resultCode == RESULT_OK && chosen != null) {
                    connect(chosen)
                } else {
                    VpnRuntime.report(VpnRuntime.State.DISCONNECTED, "Разрешение VPN не предоставлено")
                }
            }
            val connectSelected: (PublicNode) -> Unit = { node ->
                try {
                    // Validate again when connecting, never rely on feed text alone.
                    VlessProfile.parse(node.uri)
                    pendingLink = node.uri
                    val request = VpnService.prepare(this)
                    if (request == null) {
                        pendingLink = null
                        connect(node.uri)
                    } else {
                        permission.launch(request)
                    }
                } catch (_: Exception) {
                    pendingLink = null
                    error = "Не удалось запросить VPN-разрешение"
                }
            }

            OmegaScreen(
                nodesCount = nodes.size,
                selectedNumber = if (nodes.isEmpty()) 0 else position + 1,
                selectedAddress = if (nodes.isEmpty()) "" else nodes[position].host,
                riskAcknowledged = riskAcknowledged,
                onRiskAcknowledged = { riskAcknowledged = it },
                loading = loading,
                error = error,
                onConnect = {
                    if (nodes.isNotEmpty()) {
                        if (riskAcknowledged) connectSelected(nodes[position])
                        else error = "Сначала подтвердите понимание рисков публичного VPN."
                    } else if (!loading) {
                        loading = true
                        error = ""
                        scope.launch {
                            try {
                                val loaded = withContext(Dispatchers.IO) {
                                    FreeNodeRepository().load()
                                }
                                nodes = loaded
                                position = 0
                                // Security: discovery must NEVER silently connect to an unknown operator.
                                // The user must explicitly acknowledge risk and tap Connect separately.
                            } catch (_: Exception) {
                                error = "Не получилось загрузить бесплатные серверы. Проверьте интернет и повторите."
                            } finally {
                                loading = false
                            }
                        }
                    }
                },
                onNext = {
                    if (nodes.size > 1 && !loading) {
                        position = (position + 1) % nodes.size
                        error = ""
                        // Selecting another untrusted host does not initiate a VPN connection.
                    }
                },
                onRefresh = {
                    if (!loading) {
                        loading = true
                        error = ""
                        scope.launch {
                            try {
                                nodes = withContext(Dispatchers.IO) { FreeNodeRepository().load() }
                                position = 0
                            } catch (_: Exception) {
                                error = "Не удалось обновить каталог. Сохранён ранее загруженный список."
                            } finally {
                                loading = false
                            }
                        }
                    }
                },
                onDisconnect = {
                    startService(Intent(this, OmegaVpnService::class.java)
                        .setAction(OmegaVpnService.DISCONNECT))
                }
            )
        }
    }
}

@Composable
fun OmegaScreen(
    nodesCount: Int,
    selectedNumber: Int,
    selectedAddress: String,
    riskAcknowledged: Boolean,
    onRiskAcknowledged: (Boolean) -> Unit,
    loading: Boolean,
    error: String,
    onConnect: () -> Unit,
    onNext: () -> Unit,
    onRefresh: () -> Unit,
    onDisconnect: () -> Unit
) {
    val state = VpnRuntime.state
    val connected = state == VpnRuntime.State.CORE_STARTED
    val connecting = state == VpnRuntime.State.CONNECTING
    val busy = loading || connecting
    MaterialTheme {
        Surface(color = Color(0xFF101627), modifier = Modifier.fillMaxSize()) {
            Column(
                modifier = Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text("Ω VPN", fontSize = 38.sp, fontWeight = FontWeight.Bold, color = Color(0xFF8CBFFF))
                Spacer(Modifier.height(12.dp))
                Text(VpnRuntime.message, color = Color.White, textAlign = TextAlign.Center)
                Spacer(Modifier.height(18.dp))
                if (loading) CircularProgressIndicator()
                if (nodesCount > 0) {
                    Text(
                        "В каталоге: ${nodesCount} адресов (не проверены на доверие) • выбран №${selectedNumber}: ${selectedAddress}",
                        color = Color(0xFFACC2DE),
                        textAlign = TextAlign.Center,
                        fontSize = 14.sp
                    )
                } else {
                    Text("Ключи искать не нужно. Ω VPN загрузит список самостоятельно.",
                        color = Color(0xFFACC2DE), textAlign = TextAlign.Center)
                }
                if (nodesCount > 0 && !connected && !connecting) {
                    Spacer(Modifier.height(14.dp))
                    Text(
                        "ВНИМАНИЕ: владелец публичного VPN может видеть ваш реальный IP, время подключения и метаданные трафика. " +
                            "Его личность, репутация и возможная связь со спецслужбами не проверены. " +
                            "Не используйте для чувствительных данных. Список загружается с GitHub, который также видит IP при запросе.",
                        color = Color(0xFFFFC99E), fontSize = 13.sp, textAlign = TextAlign.Center
                    )
                    Spacer(Modifier.height(10.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = riskAcknowledged,
                            onCheckedChange = onRiskAcknowledged
                        )
                        Text("Понимаю риски и разрешаю попытку подключения к выбранному узлу",
                            color = Color.White, fontSize = 13.sp)
                    }
                }
                Spacer(Modifier.height(22.dp))
                if (connected || connecting) {
                    Button(onClick = onDisconnect, modifier = Modifier.fillMaxWidth()) {
                        Text("Отключить VPN")
                    }
                } else {
                    Button(
                        onClick = onConnect,
                        enabled = !busy && (nodesCount == 0 || riskAcknowledged),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(if (nodesCount == 0) "Найти бесплатные узлы" else "Подключиться к выбранному узлу")
                    }
                }
                if (nodesCount > 0 && !connected && !connecting) {
                    Spacer(Modifier.height(10.dp))
                    OutlinedButton(
                        onClick = onNext,
                        enabled = !busy && nodesCount > 1,
                        modifier = Modifier.fillMaxWidth()
                    ) { Text("Попробовать другой сервер") }
                    OutlinedButton(
                        onClick = onRefresh,
                        enabled = !busy,
                        modifier = Modifier.fillMaxWidth()
                    ) { Text("Обновить бесплатные серверы") }
                }
                if (error.isNotEmpty()) {
                    Spacer(Modifier.height(12.dp))
                    Text(error, color = Color(0xFFFFA6A6), textAlign = TextAlign.Center)
                }
                Spacer(Modifier.height(24.dp))
                Text(
                    "Источник: ${FreeNodeSource.NAME}. Публичные узлы принадлежат третьим лицам. " +
                        "Не используйте неизвестные серверы для чувствительных данных.",
                    color = Color(0xFF9CB0CB), fontSize = 12.sp, textAlign = TextAlign.Center
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    "M2/M3 • Загрузка конфигураций не гарантирует их работу. " +
                        "Реальное подключение и отсутствие DNS/IPv6-утечек ещё требуют проверки на телефоне.",
                    color = Color(0xFF9CB0CB), fontSize = 12.sp, textAlign = TextAlign.Center
                )
            }
        }
    }
}
