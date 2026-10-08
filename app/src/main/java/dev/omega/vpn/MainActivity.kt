package dev.omega.vpn

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * M1-only build spike: no VpnService, no network permission and no VPN engine.
 * Never render an enabled "connect" control before the M2 tunnel is implemented.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            OmegaHome()
        }
    }
}

private val Night = Color(0xFF0C1220)
private val Panel = Color(0xFF18263B)
private val Muted = Color(0xFF9CB0CB)
private val Accent = Color(0xFF7EB5FF)

@Composable
internal fun OmegaHome() {
    MaterialTheme {
        Surface(color = Night, modifier = Modifier.fillMaxSize()) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 22.dp, vertical = 48.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Text(
                    text = "Ω",
                    color = Accent,
                    fontSize = 76.sp,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    text = "OMEGA VPN",
                    color = Color.White,
                    fontSize = 29.sp,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    text = "Не подключено",
                    color = Muted,
                    fontSize = 16.sp
                )
                Spacer(Modifier.height(32.dp))
                Button(
                    onClick = {},
                    enabled = false,
                    modifier = Modifier.fillMaxWidth().height(56.dp),
                    colors = ButtonDefaults.buttonColors(
                        disabledContainerColor = Color(0xFF324B6A),
                        disabledContentColor = Color(0xFFBBCDE4)
                    )
                ) {
                    Text("Подключить • доступно после M2")
                }
                Spacer(Modifier.height(28.dp))
                Card(
                    colors = CardDefaults.cardColors(containerColor = Panel),
                    shape = RoundedCornerShape(20.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(22.dp)) {
                        Text("Техническая сборка M1", color = Accent, fontWeight = FontWeight.SemiBold)
                        Spacer(Modifier.height(10.dp))
                        Text(
                            "VPN-движок ещё не подключён. Приложение не изменяет интернет-трафик. " +
                                "Следующий этап: Android VpnService + Xray.",
                            color = Color.White,
                            lineHeight = 22.sp
                        )
                    }
                }
                Spacer(Modifier.height(20.dp))
                Text(
                    text = "Бесплатные узлы будут доступны после проверки безопасности и подключения.",
                    color = Muted,
                    fontSize = 13.sp,
                    textAlign = TextAlign.Center
                )
            }
        }
    }
}
