package com.aegismesh.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import androidx.core.app.NotificationCompat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.json.JSONArray;
import org.json.JSONObject;

import hev.htproxy.TProxyService;

/**
 * Реальный системный Android VPN-сервис AegisMesh VPN на базе официального ядра sing-box + hev-socks5-tunnel.
 */
public class AegisVpnService extends VpnService {
    public static final String ACTION_START = "com.aegismesh.vpn.START";
    public static final String ACTION_START_FROM_SAVED = "com.aegismesh.vpn.START_FROM_SAVED";
    public static final String ACTION_NEXT_NODE = "com.aegismesh.vpn.NEXT_NODE";
    public static final String ACTION_NEXT_AI_NODE = "com.aegismesh.vpn.NEXT_AI_NODE";
    public static final String ACTION_STOP = "com.aegismesh.vpn.STOP";
    public static final String EXTRA_CONFIG_JSON = "config_json";
    public static final String EXTRA_NODE_NAME = "node_name";
    public static final String EXTRA_OUTBOUND_TAG = "outbound_tag";
    public static final String EXTRA_DNS_SERVER = "dns_server";
    public static final String EXTRA_EXCLUDED_PACKAGES = "excluded_packages";
    public static final String EXTRA_PER_APP_MODE = "per_app_mode";
    public static final String EXTRA_PER_APP_PACKAGES = "per_app_packages";
    public static final String EXTRA_CANDIDATES_JSON = "candidates_json";
    public static final String EXTRA_WATCHDOG_JSON = "watchdog_json";

    private static final String CHANNEL_ID = "aegismesh_vpn_shield";
    private static final int NOTIFICATION_ID = 4190;
    public static final int LOCAL_MIXED_PORT = 20808;
    public static final int LOCAL_AI_PROBE_PORT = 20809;
    public static final int CLASH_API_PORT = 29090;

    private static volatile boolean sRunning = false;
    private static volatile boolean sStarting = false;
    private static volatile String sActiveNodeName = "";
    private static volatile String sActiveAiNodeName = "";
    private static volatile String sLastError = "";
    private static volatile String sLastRawConfigJson = "";
    private static volatile long sLastRebindTs = 0L;
    private static volatile boolean sCoreRestarting = false;
    private static volatile boolean sRebindInProgress = false;
    private static volatile boolean sPendingNetworkRebind = false;
    private static volatile int sRoamingHandoverCount = 0;
    private static volatile long sLastHandoverTimestamp = 0L;
    private static volatile int sActiveMtu = 1400;
    private static volatile AegisVpnService sInstance = null;
    private static final ExecutorService dnsPreResolvePool = Executors.newFixedThreadPool(10);

    private ParcelFileDescriptor vpnInterface = null;
    private Process singboxProcess = null;
    private ConnectivityManager.NetworkCallback networkCallback = null;
    private volatile String lastPhysicalNetSig = "";
    private final TProxyService tproxy = new TProxyService();
    private final StringBuilder coreLogBuffer = new StringBuilder();

    public static boolean isVpnRunning() {
        return sRunning;
    }

    public static boolean isVpnStarting() {
        return sStarting;
    }

    public static String getActiveNodeName() {
        return sActiveNodeName;
    }

    public static String getActiveAiNodeName() {
        return sActiveAiNodeName;
    }

    public static String getLastError() {
        return sLastError;
    }

    public static boolean isCoreRestarting() {
        return sCoreRestarting;
    }

    public static int getRoamingHandoverCount() {
        return sRoamingHandoverCount;
    }

    public static long getLastHandoverTimestamp() {
        return sLastHandoverTimestamp;
    }

    public static int getActiveMtu() {
        return sActiveMtu;
    }

    /**
     * Принудительно закрывает все активные и зависшие TCP/UDP соединения в ядре sing-box через Clash API (DELETE /connections).
     * Это заставляет Telegram, браузеры, YouTube и ИИ-клиенты мгновенно переоткрыть сокеты через новый маршрут или новую сеть!
     */
    public static boolean closeAllActiveConnectionsHot() {
        HttpURLConnection conn = null;
        try {
            URL url = new URL("http://127.0.0.1:" + CLASH_API_PORT + "/connections");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("DELETE");
            conn.setConnectTimeout(1200);
            conn.setReadTimeout(1200);
            int code = conn.getResponseCode();
            return code >= 200 && code < 300;
        } catch (Exception ignored) {
            return false;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    public static boolean hasSavedSession(android.content.Context ctx) {
        return AegisNativeWatchdog.hasSavedSession(ctx);
    }

    public static long[] getTrafficStats() {
        AegisVpnService inst = sInstance;
        if (inst != null && sRunning) {
            try {
                long[] stats = inst.tproxy.TProxyGetStats();
                if (stats != null && stats.length >= 4) {
                    return stats;
                }
            } catch (Throwable ignored) {
            }
        }
        return new long[]{0L, 0L, 0L, 0L};
    }

    public static boolean switchSelectorGroupHot(String selectorGroup, String outboundTag) {
        if (selectorGroup == null || selectorGroup.isEmpty() || outboundTag == null || outboundTag.isEmpty()) {
            return false;
        }
        try {
            String encGroup = URLEncoder.encode(selectorGroup.trim(), "UTF-8").replace("+", "%20");
            URL url = new URL("http://127.0.0.1:" + CLASH_API_PORT + "/proxies/" + encGroup);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("PUT");
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            conn.setDoOutput(true);
            String payload = "{\"name\":\"" + outboundTag.replace("\"", "\\\"") + "\"}";
            try (OutputStream os = conn.getOutputStream()) {
                os.write(payload.getBytes(StandardCharsets.UTF_8));
            }
            int code = conn.getResponseCode();
            conn.disconnect();
            return code >= 200 && code < 300;
        } catch (Exception ignored) {
        }
        return false;
    }

    public static boolean switchActiveOutboundHot(String outboundTag, String newNodeName) {
        if (switchSelectorGroupHot("proxy-active", outboundTag)) {
            sActiveNodeName = newNodeName;
            AegisNativeWatchdog.setActiveOutboundTag(outboundTag);
            closeAllActiveConnectionsHot();
            AegisVpnService inst = sInstance;
            if (inst != null && sRunning) {
                AegisNativeWatchdog.updateSavedActiveNode(inst, outboundTag, newNodeName);
                inst.updateForegroundNotification(newNodeName);
                AegisTileService.requestTileSync(inst);
                AegisWidgetProvider.refreshAllWidgets(inst);
            }
            return true;
        }
        return false;
    }

    public static boolean switchAiOutboundHot(String outboundTag, String aiNodeName) {
        if (switchSelectorGroupHot("proxy-ai", outboundTag)) {
            sActiveAiNodeName = aiNodeName != null ? aiNodeName : "";
            AegisNativeWatchdog.setActiveAiOutboundTag(outboundTag);
            AegisVpnService inst = sInstance;
            if (inst != null && sRunning) {
                inst.updateForegroundNotification(sActiveNodeName);
            }
            return true;
        }
        return false;
    }

    /**
     * Честная сквозная End-to-End проверка реального VPN-туннеля (TCP и UDP протоколы: VLESS, Hy2, WG, SOCKS-мост)
     * через встроенный Clash API ядра sing-box (/proxies/<tag>/delay -> cp.cloudflare.com/generate_204).
     */
    public static int probeOutboundDelay(String outboundTag, int timeoutMs) {
        return AegisNativeWatchdog.probeOutboundMultiTarget(outboundTag, timeoutMs);
    }

    /**
     * Находит активную базовую физическую сеть телефона (Wi-Fi или мобильный интернет LTE/4G/5G),
     * гарантированно исключая сам виртуальный интерфейс TRANSPORT_VPN и отдавая приоритет валидированным сетям (NET_CAPABILITY_VALIDATED).
     */
    public static Network findActivePhysicalNetwork(Context ctx) {
        return findActivePhysicalNetwork(ctx, null);
    }

    public static Network findActivePhysicalNetwork(Context ctx, Network ignoreNetwork) {
        if (ctx == null) return null;
        try {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return null;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                Network active = cm.getActiveNetwork();
                if (active != null && (ignoreNetwork == null || !active.equals(ignoreNetwork))) {
                    NetworkCapabilities caps = cm.getNetworkCapabilities(active);
                    if (caps != null
                            && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                            && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                            && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                        return active;
                    }
                }
            }
            Network[] all = cm.getAllNetworks();
            if (all != null) {
                Network validatedWifi = null;
                Network validatedCell = null;
                Network fallbackWifi = null;
                Network fallbackCell = null;
                for (Network net : all) {
                    if (net == null) continue;
                    if (ignoreNetwork != null && net.equals(ignoreNetwork)) continue;
                    NetworkCapabilities caps = cm.getNetworkCapabilities(net);
                    if (caps == null) continue;
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
                    if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
                    boolean validated = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
                            && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
                    boolean isWifiOrEth = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                            || caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET);
                    boolean isCell = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR);
                    if (isWifiOrEth) {
                        if (validated && validatedWifi == null) validatedWifi = net;
                        else if (fallbackWifi == null) fallbackWifi = net;
                    } else if (isCell) {
                        if (validated && validatedCell == null) validatedCell = net;
                        else if (fallbackCell == null) fallbackCell = net;
                    }
                }
                if (validatedWifi != null) return validatedWifi;
                if (validatedCell != null) return validatedCell;
                if (fallbackWifi != null) return fallbackWifi;
                if (fallbackCell != null) return fallbackCell;
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * Возвращает тип активной физической сети: "cellular" (мобильный интернет 4G/LTE/5G), "wifi" или "unknown".
     */
    public static String detectActiveNetworkType(Context ctx) {
        if (ctx == null) return "unknown";
        try {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return "unknown";
            Network phys = findActivePhysicalNetwork(ctx);
            if (phys != null) {
                NetworkCapabilities caps = cm.getNetworkCapabilities(phys);
                if (caps != null) {
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) return "cellular";
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return "wifi";
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) return "ethernet";
                }
            }
        } catch (Exception ignored) {
        }
        return "unknown";
    }

    private static boolean isRawIpLiteral(String host) {
        if (host == null || host.isEmpty()) return true;
        if (host.contains(":")) return true; // IPv6
        if ("localhost".equalsIgnoreCase(host)) return true;
        return host.matches("^\\d{1,3}(\\.\\d{1,3}){3}$");
    }

    /**
     * Пред-резолвит доменные имена всех VPN-серверов в чистые IPv4-адреса напрямую через системный DNS
     * активной физической сети Android (LTE / Wi-Fi) ДО запуска sing-box!
     * Это полностью устраняет проблему блокировки внешнего UDP DNS (1.1.1.1:53) мобильными операторами РФ (МТС, МегаФон, Билайн, Т2).
     */
    public static String preResolveConfigServerDomains(Context ctx, String rawConfigJson) {
        if (rawConfigJson == null || rawConfigJson.trim().isEmpty()) return rawConfigJson;
        try {
            JSONObject root = new JSONObject(rawConfigJson);
            Set<String> domainsToResolve = new HashSet<>();

            JSONArray outbounds = root.optJSONArray("outbounds");
            String currentMainTag = AegisNativeWatchdog.getActiveOutboundTag();
            String currentAiTag = AegisNativeWatchdog.getActiveAiOutboundTag();
            if (outbounds != null) {
                for (int i = 0; i < outbounds.length(); i++) {
                    JSONObject ob = outbounds.optJSONObject(i);
                    if (ob == null) continue;
                    // Патчим default у селекторов proxy-active и proxy-ai, чтобы при горячем рестарте sing-box
                    // он сразу поднимался на последнем выбранном сервере, а не откатывался к стартовому!
                    String tag = ob.optString("tag", "");
                    if ("proxy-active".equals(tag) && currentMainTag != null && !currentMainTag.isEmpty()) {
                        JSONArray list = ob.optJSONArray("outbounds");
                        if (list != null) {
                            for (int k = 0; k < list.length(); k++) {
                                if (currentMainTag.equals(list.optString(k, ""))) {
                                    ob.put("default", currentMainTag);
                                    break;
                                }
                            }
                        }
                    } else if ("proxy-ai".equals(tag) && currentAiTag != null && !currentAiTag.isEmpty()) {
                        JSONArray list = ob.optJSONArray("outbounds");
                        if (list != null) {
                            for (int k = 0; k < list.length(); k++) {
                                if (currentAiTag.equals(list.optString(k, ""))) {
                                    ob.put("default", currentAiTag);
                                    break;
                                }
                            }
                        }
                    }
                    String srv = ob.optString("server", "").trim();
                    if (!srv.isEmpty() && !isRawIpLiteral(srv)) {
                        domainsToResolve.add(srv);
                    }
                }
            }

            JSONArray endpoints = root.optJSONArray("endpoints");
            if (endpoints != null) {
                for (int i = 0; i < endpoints.length(); i++) {
                    JSONObject ep = endpoints.optJSONObject(i);
                    if (ep == null) continue;
                    JSONArray peers = ep.optJSONArray("peers");
                    if (peers == null) continue;
                    for (int j = 0; j < peers.length(); j++) {
                        JSONObject peer = peers.optJSONObject(j);
                        if (peer == null) continue;
                        String addr = peer.optString("address", "").trim();
                        if (!addr.isEmpty() && !isRawIpLiteral(addr)) {
                            domainsToResolve.add(addr);
                        }
                    }
                }
            }

            if (domainsToResolve.isEmpty()) return root.toString();

            final Network physNet = findActivePhysicalNetwork(ctx);
            List<Callable<String[]>> tasks = new ArrayList<>();
            for (final String domain : domainsToResolve) {
                tasks.add(() -> {
                    try {
                        InetAddress[] addrs = (physNet != null)
                                ? physNet.getAllByName(domain)
                                : InetAddress.getAllByName(domain);
                        if (addrs != null && addrs.length > 0) {
                            String fallbackIp = null;
                            for (InetAddress a : addrs) {
                                if (a == null || a.isLoopbackAddress() || a.isAnyLocalAddress()) continue;
                                String ip = a.getHostAddress();
                                if (ip == null || ip.startsWith("10.14.0.") || ip.startsWith("127.")) continue;
                                if (a instanceof Inet4Address) {
                                    return new String[]{domain, ip};
                                }
                                if (fallbackIp == null) fallbackIp = ip;
                            }
                            if (fallbackIp != null) {
                                return new String[]{domain, fallbackIp};
                            }
                        }
                    } catch (Exception ignored) {
                    }
                    return null;
                });
            }

            List<Future<String[]>> futures = dnsPreResolvePool.invokeAll(tasks, 1800L, TimeUnit.MILLISECONDS);
            Map<String, String> resolvedMap = new HashMap<>();
            for (Future<String[]> f : futures) {
                if (f.isDone() && !f.isCancelled()) {
                    try {
                        String[] pair = f.get();
                        if (pair != null && pair.length == 2 && pair[1] != null && !pair[1].isEmpty()) {
                            resolvedMap.put(pair[0], pair[1]);
                        }
                    } catch (Exception ignored) {
                    }
                }
            }

            if (resolvedMap.isEmpty()) return root.toString();

            if (outbounds != null) {
                for (int i = 0; i < outbounds.length(); i++) {
                    JSONObject ob = outbounds.optJSONObject(i);
                    if (ob == null) continue;
                    String srv = ob.optString("server", "").trim();
                    String resolvedIp = resolvedMap.get(srv);
                    if (resolvedIp != null) {
                        JSONObject tls = ob.optJSONObject("tls");
                        if (tls != null && tls.optBoolean("enabled", false)) {
                            String sni = tls.optString("server_name", "").trim();
                            if (sni.isEmpty()) {
                                tls.put("server_name", srv);
                            }
                        }
                        ob.put("server", resolvedIp);
                    }
                }
            }

            if (endpoints != null) {
                for (int i = 0; i < endpoints.length(); i++) {
                    JSONObject ep = endpoints.optJSONObject(i);
                    if (ep == null) continue;
                    JSONArray peers = ep.optJSONArray("peers");
                    if (peers == null) continue;
                    for (int j = 0; j < peers.length(); j++) {
                        JSONObject peer = peers.optJSONObject(j);
                        if (peer == null) continue;
                        String addr = peer.optString("address", "").trim();
                        String resolvedIp = resolvedMap.get(addr);
                        if (resolvedIp != null) {
                            peer.put("address", resolvedIp);
                        }
                    }
                }
            }

            return root.toString();
        } catch (Exception ignored) {
            return rawConfigJson;
        }
    }

    /**
     * Горячий перезапуск процесса sing-box без закрытия системного TUN-интерфейса при смене сети (Wi-Fi ↔ LTE)
     * или при зависании UDP/QUIC сокетов на старом мобильном интерфейсе.
     */
    public static boolean rebindAndRestartSingboxHot(String reason) {
        return rebindAndRestartSingboxHot(reason, false);
    }

    public static boolean rebindAndRestartSingboxHot(String reason, boolean force) {
        AegisVpnService inst = sInstance;
        if (inst == null || !sRunning) return false;
        long now = System.currentTimeMillis();
        if (!force && now - sLastRebindTs < 1200L) {
            sPendingNetworkRebind = true;
            return false;
        }
        sLastRebindTs = now;
        return inst.restartSingboxCoreOnlyInternal(reason);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        sInstance = this;
        ensureNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null || ACTION_STOP.equals(intent.getAction())) {
            stopTunnelCleanly();
            stopSelf();
            return START_NOT_STICKY;
        }

        if (ACTION_NEXT_NODE.equals(intent.getAction())) {
            if (sRunning) {
                updateForegroundNotification("⏳ Подбор лучшего сервера...");
                new Thread(
                        () -> AegisNativeWatchdog.switchNextOrRaceManual(getApplicationContext()),
                        "AegisNextNode"
                ).start();
                return START_STICKY;
            }
            stopSelf();
            return START_NOT_STICKY;
        }

        if (ACTION_NEXT_AI_NODE.equals(intent.getAction())) {
            if (sRunning) {
                new Thread(
                        () -> AegisNativeWatchdog.switchNextAiManual(getApplicationContext()),
                        "AegisNextAiNode"
                ).start();
                return START_STICKY;
            }
            stopSelf();
            return START_NOT_STICKY;
        }

        if (ACTION_START_FROM_SAVED.equals(intent.getAction())) {
            JSONObject saved = AegisNativeWatchdog.loadSession(this);
            if (saved == null) {
                stopSelf();
                return START_NOT_STICKY;
            }
            final String configJson = saved.optString("configJson", "");
            final String nodeName = saved.optString("nodeName", "Каскад AegisMesh");
            final String outboundTag = saved.optString("outboundTag", "");
            final String dnsServer = saved.optString("dnsServer", "1.1.1.1");
            final String excludedPackages = saved.optString("excludedPackages", "");
            final String perAppMode = saved.optString("perAppMode", "all");
            final String perAppPackages = saved.optString("perAppPackages", "");
            final String candidatesJson = saved.optString("candidatesJson", "[]");
            final String watchdogJson = saved.optString("watchdogJson", "{}");

            sStarting = true;
            sLastError = "";
            promoteToForeground(nodeName);
            new Thread(
                    () -> startTunnelInternal(
                            configJson,
                            nodeName,
                            outboundTag,
                            dnsServer,
                            excludedPackages,
                            perAppMode,
                            perAppPackages,
                            candidatesJson,
                            watchdogJson
                    ),
                    "AegisVpnSavedStarter"
            ).start();
            return START_STICKY;
        }

        if (ACTION_START.equals(intent.getAction())) {
            final String configJson = intent.getStringExtra(EXTRA_CONFIG_JSON);
            final String nodeName = intent.getStringExtra(EXTRA_NODE_NAME);
            final String outboundTag = intent.getStringExtra(EXTRA_OUTBOUND_TAG);
            final String dnsServer = intent.getStringExtra(EXTRA_DNS_SERVER);
            final String excludedPackages = intent.getStringExtra(EXTRA_EXCLUDED_PACKAGES);
            final String perAppMode = intent.getStringExtra(EXTRA_PER_APP_MODE);
            final String perAppPackages = intent.getStringExtra(EXTRA_PER_APP_PACKAGES);
            final String candidatesJson = intent.getStringExtra(EXTRA_CANDIDATES_JSON);
            final String watchdogJson = intent.getStringExtra(EXTRA_WATCHDOG_JSON);

            sStarting = true;
            sLastError = "";
            String displayNode = (nodeName != null && !nodeName.isEmpty()) ? nodeName : "Каскад AegisMesh";
            AegisNativeWatchdog.saveSession(
                    this,
                    configJson,
                    displayNode,
                    outboundTag,
                    dnsServer,
                    excludedPackages,
                    perAppMode,
                    perAppPackages,
                    candidatesJson,
                    watchdogJson
            );
            promoteToForeground(displayNode);

            new Thread(
                    () -> startTunnelInternal(
                            configJson,
                            displayNode,
                            outboundTag,
                            dnsServer,
                            excludedPackages,
                            perAppMode,
                            perAppPackages,
                            candidatesJson,
                            watchdogJson
                    ),
                    "AegisVpnStarter"
            ).start();
            return START_STICKY;
        }

        return START_NOT_STICKY;
    }

    private synchronized void startTunnelInternal(
            String configJson,
            String nodeName,
            String outboundTag,
            String dnsServer,
            String excludedPackages,
            String perAppMode,
            String perAppPackages,
            String candidatesJson,
            String watchdogJson
    ) {
        try {
            stopTunnelProcessesOnly();

            if (configJson == null || configJson.trim().isEmpty()) {
                throw new IllegalArgumentException("Пустая конфигурация VPN-туннеля");
            }
            sLastRawConfigJson = configJson;
            // Инициализируем активные теги селекторов proxy-active и proxy-ai из конфига до старта
            if (outboundTag != null && !outboundTag.isEmpty()) {
                AegisNativeWatchdog.setActiveOutboundTag(outboundTag);
            }
            try {
                JSONObject cfgObj = new JSONObject(configJson);
                JSONArray obs = cfgObj.optJSONArray("outbounds");
                if (obs != null) {
                    for (int i = 0; i < obs.length(); i++) {
                        JSONObject ob = obs.optJSONObject(i);
                        if (ob != null && "proxy-ai".equals(ob.optString("tag", ""))) {
                            String defAi = ob.optString("default", "");
                            if (!defAi.isEmpty()) {
                                AegisNativeWatchdog.setActiveAiOutboundTag(defAi);
                            }
                            break;
                        }
                    }
                }
            } catch (Exception ignored) {
            }

            bindToActivePhysicalNetwork(null);
            String preparedConfigJson = preResolveConfigServerDomains(this, configJson);

            File workDir = getFilesDir();
            File singboxConfigFile = new File(workDir, "aegis-singbox.json");
            writeTextFile(singboxConfigFile, preparedConfigJson);

            // Адаптивный MTU: 1360 байт на мобильном интернете (LTE/4G/5G) для защиты от фрагментации GTP-пакетов, 1400 байт на Wi-Fi
            boolean adaptiveMtu = true;
            try {
                if (watchdogJson != null && !watchdogJson.isEmpty()) {
                    JSONObject wj = new JSONObject(watchdogJson);
                    adaptiveMtu = wj.optBoolean("adaptiveMobileMtu", true);
                }
            } catch (Exception ignored) {
            }
            boolean isCellNow = "cellular".equals(detectActiveNetworkType(this));
            int tunnelMtu = (adaptiveMtu && isCellNow) ? 1360 : 1400;
            sActiveMtu = tunnelMtu;

            File hevConfigFile = new File(workDir, "aegis-hev.yml");
            String hevYaml = "tunnel:\n"
                    + "  mtu: " + tunnelMtu + "\n"
                    + "  ipv4: 10.14.0.1\n"
                    + "socks5:\n"
                    + "  port: " + LOCAL_MIXED_PORT + "\n"
                    + "  address: 127.0.0.1\n"
                    + "  udp: 'udp'\n"
                    + "misc:\n"
                    + "  task-stack-size: 86016\n"
                    + "  connect-timeout: 10000\n"
                    + "  tcp-read-write-timeout: 300000\n"
                    + "  udp-read-write-timeout: 60000\n"
                    + "  log-level: warn\n";
            writeTextFile(hevConfigFile, hevYaml);

            String nativeDir = getApplicationInfo().nativeLibraryDir;
            File singboxBin = new File(nativeDir, "libsingbox.so");
            if (!singboxBin.exists()) {
                throw new IllegalStateException("Нативное ядро libsingbox.so не найдено в " + nativeDir);
            }
            singboxBin.setExecutable(true, false);

            synchronized (coreLogBuffer) {
                coreLogBuffer.setLength(0);
            }

            ProcessBuilder pb = new ProcessBuilder(
                    singboxBin.getAbsolutePath(),
                    "run",
                    "-c",
                    singboxConfigFile.getAbsolutePath(),
                    "-D",
                    workDir.getAbsolutePath()
            );
            pb.directory(workDir);
            pb.redirectErrorStream(true);
            singboxProcess = pb.start();

            final Process procRef = singboxProcess;
            new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(procRef.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        synchronized (coreLogBuffer) {
                            if (coreLogBuffer.length() > 4000) {
                                coreLogBuffer.delete(0, 2000);
                            }
                            coreLogBuffer.append(line).append('\n');
                        }
                    }
                } catch (Exception ignored) {
                }
            }, "SingboxLogReader").start();

            // Ожидаем открытия локального прокси-порта sing-box 127.0.0.1:20808 и контроллера Clash API 127.0.0.1:29090
            boolean portReady = false;
            long deadline = System.currentTimeMillis() + 4500L;
            while (System.currentTimeMillis() < deadline) {
                if (!isProcessAlive(singboxProcess)) {
                    break;
                }
                try (Socket probe = new Socket(); Socket apiProbe = new Socket()) {
                    probe.connect(new InetSocketAddress("127.0.0.1", LOCAL_MIXED_PORT), 200);
                    apiProbe.connect(new InetSocketAddress("127.0.0.1", CLASH_API_PORT), 200);
                    portReady = true;
                    break;
                } catch (Exception ignored) {
                    Thread.sleep(100);
                }
            }

            if (!portReady) {
                String logTail;
                synchronized (coreLogBuffer) {
                    logTail = coreLogBuffer.toString().trim();
                }
                throw new IllegalStateException(
                        logTail.isEmpty()
                                ? "Ядро sing-box не открыло порт туннеля (проверьте корректность VPN-ключа)"
                                : "Ошибка ядра sing-box: " + logTail
                );
            }

            // Поднимаем системный Android TUN-интерфейс
            Builder builder = new Builder();
            builder.setSession("AegisMesh VPN • " + nodeName);
            builder.setMtu(tunnelMtu);
            builder.addAddress("10.14.0.1", 30);
            builder.addRoute("0.0.0.0", 0);
            String cleanDns = (dnsServer != null && !dnsServer.trim().isEmpty()) ? dnsServer.trim() : "1.1.1.1";
            builder.addDnsServer(cleanDns);

            // Формируем список пакетов, которые НИКОГДА не должны попадать в TUN (сам AegisMesh + внешние мосты 127.0.0.1)
            String selfPkg = getPackageName();
            Set<String> mustBypassSet = new HashSet<>();
            mustBypassSet.add(selfPkg);
            if (excludedPackages != null && !excludedPackages.trim().isEmpty()) {
                for (String rawPkg : excludedPackages.split(",")) {
                    String pkg = rawPkg != null ? rawPkg.trim() : "";
                    if (!pkg.isEmpty()) {
                        mustBypassSet.add(pkg);
                    }
                }
            }

            // Умная маршрутизация по приложениям (Per-App VPN v3.0):
            // "only_selected" — в VPN идут ТОЛЬКО отмеченные пользователем приложения (кроме mustBypassSet).
            // "exclude_selected" / "all" — в VPN идут все приложения, кроме mustBypassSet и исключённых пользователем.
            boolean appliedAllowedMode = false;
            if ("only_selected".equals(perAppMode) && perAppPackages != null && !perAppPackages.trim().isEmpty()) {
                int addedAllowed = 0;
                for (String rawPkg : perAppPackages.split(",")) {
                    String pkg = rawPkg != null ? rawPkg.trim() : "";
                    if (!pkg.isEmpty() && !mustBypassSet.contains(pkg)) {
                        try {
                            builder.addAllowedApplication(pkg);
                            addedAllowed++;
                        } catch (Exception ignored) {
                        }
                    }
                }
                if (addedAllowed > 0) {
                    appliedAllowedMode = true;
                }
            }

            if (!appliedAllowedMode) {
                for (String bypassPkg : mustBypassSet) {
                    try {
                        builder.addDisallowedApplication(bypassPkg);
                    } catch (Exception ignored) {
                    }
                }
                if ("exclude_selected".equals(perAppMode) && perAppPackages != null && !perAppPackages.trim().isEmpty()) {
                    for (String rawPkg : perAppPackages.split(",")) {
                        String pkg = rawPkg != null ? rawPkg.trim() : "";
                        if (!pkg.isEmpty() && !mustBypassSet.contains(pkg)) {
                            try {
                                builder.addDisallowedApplication(pkg);
                            } catch (Exception ignored) {
                            }
                        }
                    }
                }
            }

            vpnInterface = builder.establish();
            if (vpnInterface == null) {
                throw new IllegalStateException("Система Android отклонила создание TUN-интерфейса (разрешите VPN)");
            }
            bindToActivePhysicalNetwork(null);

            boolean tunnelStarted = tproxy.TProxyStartService(hevConfigFile.getAbsolutePath(), vpnInterface.getFd());
            if (!tunnelStarted) {
                throw new IllegalStateException("Не удалось запустить пакетный мост TUN -> sing-box");
            }

            sActiveNodeName = nodeName;
            sRunning = true;
            sStarting = false;
            registerUnderlyingNetworkMonitor();
            updateForegroundNotification(nodeName);
            AegisNativeWatchdog.startWatchdogLoop(getApplicationContext(), outboundTag, candidatesJson, watchdogJson);
            AegisTileService.requestTileSync(this);
            AegisWidgetProvider.refreshAllWidgets(this);
        } catch (Throwable err) {
            sLastError = err.getMessage() != null ? err.getMessage() : err.toString();
            sRunning = false;
            sStarting = false;
            stopTunnelCleanly();
            stopSelf();
        }
    }

    private Network bindToActivePhysicalNetwork(Network ignoreNetwork) {
        Network phys = findActivePhysicalNetwork(this, ignoreNetwork);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            try {
                if (phys != null) {
                    setUnderlyingNetworks(new Network[]{phys});
                } else {
                    setUnderlyingNetworks(null);
                }
            } catch (Exception ignored) {
            }
        }
        return phys;
    }

    private String buildPhysicalNetworkSignature(ConnectivityManager cm, Network physNet) {
        if (cm == null || physNet == null) return "";
        try {
            String type = "unknown";
            NetworkCapabilities caps = cm.getNetworkCapabilities(physNet);
            if (caps != null) {
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) type = "cellular";
                else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) type = "wifi";
                else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) type = "ethernet";
            }
            String iface = "";
            LinkProperties lp = cm.getLinkProperties(physNet);
            if (lp != null && lp.getInterfaceName() != null) {
                iface = lp.getInterfaceName();
            }
            return physNet.toString() + ":" + type + ":" + iface;
        } catch (Exception ignored) {
            return physNet.toString();
        }
    }

    private void registerUnderlyingNetworkMonitor() {
        unregisterUnderlyingNetworkMonitor();
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1) return;
        try {
            final ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return;
            Network initial = findActivePhysicalNetwork(this, null);
            lastPhysicalNetSig = buildPhysicalNetworkSignature(cm, initial);

            NetworkRequest req = new NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build();

            networkCallback = new ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(Network network) {
                    schedulePhysicalNetworkShift(null);
                }

                @Override
                public void onCapabilitiesChanged(Network network, NetworkCapabilities networkCapabilities) {
                    if (networkCapabilities != null
                            && !networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                            && networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                        schedulePhysicalNetworkShift(null);
                    }
                }

                @Override
                public void onLinkPropertiesChanged(Network network, LinkProperties linkProperties) {
                    schedulePhysicalNetworkShift(null);
                }

                @Override
                public void onLost(Network network) {
                    // Критически важно при выходе из дома / выключении Wi-Fi:
                    // LTE уже был поднят в фоне, поэтому срабатывает onLost(wifiNetwork), а не onAvailable(lte)!
                    schedulePhysicalNetworkShift(network);
                }
            };
            cm.registerNetworkCallback(req, networkCallback);
        } catch (Exception ignored) {
        }
    }

    /**
     * Интеллектуальный Debounce-планировщик смены сети (Wi-Fi 1 -> Wi-Fi 2 и Wi-Fi <-> Мобильная сеть LTE/4G):
     * 1) Всегда находит реальную лучшую валидированную сеть (исключая умирающую lostNetwork);
     * 2) Не теряет финальное переключение при быстром переходе Wi-Fi 1 -> LTE (0.8с) -> Wi-Fi 2 (Pending Rebind);
     * 3) Горячо перезапускает сокеты sing-box с повторным пред-резолвом доменов и запускает 1.5-секундный хэндовер!
     */
    private void schedulePhysicalNetworkShift(final Network lostNetwork) {
        if (!sRunning) return;
        try {
            final ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return;
            Network bestPhys = bindToActivePhysicalNetwork(lostNetwork);
            if (bestPhys == null) return;

            final String newSig = buildPhysicalNetworkSignature(cm, bestPhys);
            String prevSig = lastPhysicalNetSig;
            if (prevSig == null || prevSig.isEmpty()) {
                lastPhysicalNetSig = newSig;
                return;
            }
            if (prevSig.equals(newSig)) return;

            lastPhysicalNetSig = newSig;
            if (sRebindInProgress) {
                sPendingNetworkRebind = true;
                return;
            }
            sRebindInProgress = true;

            new Thread(() -> {
                try {
                    do {
                        sPendingNetworkRebind = false;
                        // Короткая пауза 350 мс для завершения DHCP/DNS при переходе между Wi-Fi роутерами или LTE
                        Thread.sleep(350);
                        if (!sRunning) break;
                        bindToActivePhysicalNetwork(null);
                        String netType = detectActiveNetworkType(this);
                        sRoamingHandoverCount += 1;
                        sLastHandoverTimestamp = System.currentTimeMillis();
                        String label = "cellular".equals(netType)
                                ? "Бесшовный переход на мобильную сеть (LTE/4G)"
                                : "Бесшовный переход на сеть Wi-Fi";
                        boolean ok = rebindAndRestartSingboxHot(label, true);
                        updateForegroundNotification(sActiveNodeName);
                        if (ok && !sPendingNetworkRebind) {
                            AegisNativeWatchdog.onPhysicalNetworkHandover(getApplicationContext(), netType, label);
                        }
                    } while (sPendingNetworkRebind && sRunning);
                } catch (Exception ignored) {
                } finally {
                    sRebindInProgress = false;
                }
            }, "AegisNetworkShiftRebinder").start();
        } catch (Exception ignored) {
            sRebindInProgress = false;
        }
    }

    private void unregisterUnderlyingNetworkMonitor() {
        if (networkCallback != null) {
            try {
                ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) {
                    cm.unregisterNetworkCallback(networkCallback);
                }
            } catch (Exception ignored) {
            }
            networkCallback = null;
        }
    }

    /**
     * Перезапускает только процесс libsingbox.so (с повторным пред-резолвом доменов через новый LTE/Wi-Fi интерфейс),
     * сохраняя открытым системный TUN-интерфейс и tproxy, чтобы сбросить зависшие на старой сети QUIC/UDP/TCP сокеты!
     */
    private synchronized boolean restartSingboxCoreOnlyInternal(String reason) {
        if (!sRunning) return false;
        sCoreRestarting = true;
        try {
            bindToActivePhysicalNetwork(null);
            String rawCfg = sLastRawConfigJson;
            File workDir = getFilesDir();
            File singboxConfigFile = new File(workDir, "aegis-singbox.json");
            if (rawCfg != null && !rawCfg.trim().isEmpty()) {
                String prepared = preResolveConfigServerDomains(this, rawCfg);
                writeTextFile(singboxConfigFile, prepared);
            }

            if (singboxProcess != null) {
                try {
                    singboxProcess.destroy();
                } catch (Exception ignored) {
                }
                singboxProcess = null;
            }

            String nativeDir = getApplicationInfo().nativeLibraryDir;
            File singboxBin = new File(nativeDir, "libsingbox.so");
            if (!singboxBin.exists()) return false;
            singboxBin.setExecutable(true, false);

            ProcessBuilder pb = new ProcessBuilder(
                    singboxBin.getAbsolutePath(),
                    "run",
                    "-c",
                    singboxConfigFile.getAbsolutePath(),
                    "-D",
                    workDir.getAbsolutePath()
            );
            pb.directory(workDir);
            pb.redirectErrorStream(true);
            singboxProcess = pb.start();

            final Process procRef = singboxProcess;
            new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(procRef.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        synchronized (coreLogBuffer) {
                            if (coreLogBuffer.length() > 4000) {
                                coreLogBuffer.delete(0, 2000);
                            }
                            coreLogBuffer.append(line).append('\n');
                        }
                    }
                } catch (Exception ignored) {
                }
            }, "SingboxRebindLogReader").start();

            boolean portReady = false;
            long deadline = System.currentTimeMillis() + 4200L;
            while (System.currentTimeMillis() < deadline) {
                if (!isProcessAlive(singboxProcess)) break;
                try (Socket probe = new Socket(); Socket apiProbe = new Socket()) {
                    probe.connect(new InetSocketAddress("127.0.0.1", LOCAL_MIXED_PORT), 200);
                    apiProbe.connect(new InetSocketAddress("127.0.0.1", CLASH_API_PORT), 200);
                    portReady = true;
                    break;
                } catch (Exception ignored) {
                    Thread.sleep(100);
                }
            }

            if (portReady) {
                String activeMainTag = AegisNativeWatchdog.getActiveOutboundTag();
                if (activeMainTag != null && !activeMainTag.isEmpty()) {
                    switchSelectorGroupHot("proxy-active", activeMainTag);
                }
                String activeAiTag = AegisNativeWatchdog.getActiveAiOutboundTag();
                if (activeAiTag != null && !activeAiTag.isEmpty()) {
                    switchSelectorGroupHot("proxy-ai", activeAiTag);
                }
            }
            return portReady;
        } catch (Exception ignored) {
            return false;
        } finally {
            sCoreRestarting = false;
        }
    }

    private void stopTunnelProcessesOnly() {
        try {
            if (tproxy.TProxyIsRunning()) {
                tproxy.TProxyStopService();
            }
        } catch (Throwable ignored) {
        }

        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception ignored) {
            }
            vpnInterface = null;
        }

        if (singboxProcess != null) {
            try {
                singboxProcess.destroy();
            } catch (Exception ignored) {
            }
            singboxProcess = null;
        }
    }

    private synchronized void stopTunnelCleanly() {
        sRunning = false;
        sStarting = false;
        sActiveNodeName = "";
        sActiveAiNodeName = "";
        AegisNativeWatchdog.setActiveAiOutboundTag("");
        AegisNativeWatchdog.stopWatchdogLoop();
        unregisterUnderlyingNetworkMonitor();
        stopTunnelProcessesOnly();
        try {
            stopForeground(true);
        } catch (Exception ignored) {
        }
        AegisTileService.requestTileSync(this);
        AegisWidgetProvider.refreshAllWidgets(this);
    }

    @Override
    public void onRevoke() {
        stopTunnelCleanly();
        stopSelf();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        stopTunnelCleanly();
        if (sInstance == this) {
            sInstance = null;
        }
        super.onDestroy();
    }

    private boolean isProcessAlive(Process p) {
        if (p == null) return false;
        try {
            p.exitValue();
            return false;
        } catch (IllegalThreadStateException e) {
            return true;
        }
    }

    private void writeTextFile(File file, String content) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(file, false)) {
            fos.write(content.getBytes(StandardCharsets.UTF_8));
            fos.flush();
        }
    }

    private void ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "Защитный туннель AegisMesh VPN",
                    NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("Статус активного шифрованного туннеля и каскадной автозамены");
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) {
                nm.createNotificationChannel(channel);
            }
        }
    }

    private Notification buildNotification(String nodeName) {
        Intent openIntent = new Intent(this, MainActivity.class);
        openIntent.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        int piFlags = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
                ? PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
                : PendingIntent.FLAG_UPDATE_CURRENT;
        PendingIntent contentIntent = PendingIntent.getActivity(this, 0, openIntent, piFlags);

        Intent nextIntent = new Intent(this, AegisVpnService.class);
        nextIntent.setAction(ACTION_NEXT_NODE);
        PendingIntent nextPending = PendingIntent.getService(this, 2, nextIntent, piFlags);

        Intent nextAiIntent = new Intent(this, AegisVpnService.class);
        nextAiIntent.setAction(ACTION_NEXT_AI_NODE);
        PendingIntent nextAiPending = PendingIntent.getService(this, 3, nextAiIntent, piFlags);

        Intent stopIntent = new Intent(this, AegisVpnService.class);
        stopIntent.setAction(ACTION_STOP);
        PendingIntent stopPending = PendingIntent.getService(this, 1, stopIntent, piFlags);

        String netType = detectActiveNetworkType(this);
        String netBadge = "cellular".equals(netType)
                ? "📶 LTE/4G"
                : ("wifi".equals(netType) ? "🏠 Wi-Fi" : "🌐 Сеть");
        String aiPart = (sActiveAiNodeName != null && !sActiveAiNodeName.isEmpty())
                ? (" • 🤖 ИИ: " + sActiveAiNodeName)
                : "";

        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("AegisMesh VPN • " + netBadge + " • Роуминг 24/7")
                .setContentText("VPN: " + nodeName + aiPart)
                .setSmallIcon(R.drawable.ic_aegis_shield)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setContentIntent(contentIntent)
                .addAction(android.R.drawable.ic_popup_sync, "🔄 Сменить VPN", nextPending)
                .addAction(android.R.drawable.ic_menu_manage, "🤖 Сменить ИИ", nextAiPending)
                .addAction(android.R.drawable.ic_menu_close_clear_cancel, "📴 Стоп", stopPending)
                .build();
    }

    private void promoteToForeground(String nodeName) {
        Notification notification = buildNotification(nodeName);
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }

    private void updateForegroundNotification(String nodeName) {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm != null) {
            nm.notify(NOTIFICATION_ID, buildNotification(nodeName));
        }
    }
}
