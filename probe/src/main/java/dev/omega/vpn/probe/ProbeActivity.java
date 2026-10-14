package dev.omega.vpn.probe;

import android.app.Activity;
import android.os.Bundle;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.util.Log;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import javax.net.ssl.HttpsURLConnection;

/** Different UID from the VPN client: tests real system VPN routing. */
public final class ProbeActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        final String nonce = getIntent().getStringExtra("nonce");
        final String salt = getIntent().getStringExtra("salt");
        new Thread(() -> {
            HttpsURLConnection conn = null;
            String result = "FAIL";
            try {
                if (nonce == null || !nonce.matches("[A-Za-z0-9_]{1,32}") ||
                    salt == null || salt.length() < 12) {
                    throw new IllegalArgumentException("Missing nonce/salt");
                }
                ConnectivityManager cm = (ConnectivityManager)
                    getSystemService(CONNECTIVITY_SERVICE);
                Network network = cm.getActiveNetwork();
                NetworkCapabilities capabilities = cm.getNetworkCapabilities(network);
                boolean vpnDefault = capabilities != null &&
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
                conn = (HttpsURLConnection) new URL("https://api.ipify.org").openConnection();
                conn.setConnectTimeout(10000);
                conn.setReadTimeout(10000);
                conn.setInstanceFollowRedirects(false);
                int status = conn.getResponseCode();
                if (status != HttpURLConnection.HTTP_OK) {
                    throw new IllegalStateException("HTTP_" + status);
                }
                String ip;
                try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    ip = reader.readLine();
                }
                if (ip == null || ip.length() > 45 || ip.length() < 7) {
                    throw new IllegalStateException("IP_BAD_RESPONSE");
                }
                String family = ip.contains(":") ? "6" : "4";
                // Avoid publishing the emulator's real public IP in GitHub logs.
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] digest = md.digest((salt + ":" + ip).getBytes(StandardCharsets.UTF_8));
                StringBuilder hash = new StringBuilder();
                for (byte b : digest) hash.append(String.format(Locale.US, "%02x", b & 0xff));
                InetAddress[] dns = InetAddress.getAllByName("www.cloudflare.com");
                if (dns.length == 0) throw new IllegalStateException("DNS_UNRESOLVED");
                result = "PASS http=200 family=" + family +
                         " iphash=" + hash + " dns=PASS vpn=" + (vpnDefault ? "1" : "0");
            } catch (Throwable error) {
                result = "FAIL reason=" + error.getClass().getSimpleName();
            } finally {
                if (conn != null) conn.disconnect();
                Log.i("OMEGA_PROBE", "nonce=" + (nonce == null ? "NONE" : nonce) + " " + result);
                runOnUiThread(this::finish);
            }
        }, "omega-e2e-network-probe").start();
    }
}
