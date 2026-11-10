package com.aegismesh.vpn;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Network;
import android.net.VpnService;
import android.os.Build;

import androidx.activity.result.ActivityResult;

import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.ActivityCallback;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Нативный Capacitor-плагин AegisNativeVpn:
 * управление реальным VpnService + sing-box, нативный TCP-пинг серверов пользователя,
 * загрузка подписок без CORS и проверка внешнего IP сквозь туннель.
 */
@CapacitorPlugin(name = "AegisNativeVpn")
public class AegisNativeVpnPlugin extends Plugin {
    private final ExecutorService ioPool = Executors.newCachedThreadPool();

    @PluginMethod
    public void startVpn(PluginCall call) {
        String configJson = call.getString("configJson", "");
        if (configJson == null || configJson.trim().isEmpty()) {
            call.reject("Пустая конфигурация VPN. Добавьте хотя бы один VPN-ключ.");
            return;
        }

        Activity activity = getActivity();
        if (activity == null) {
            call.reject("Активность Android недоступна");
            return;
        }

        Intent prepareIntent = VpnService.prepare(activity);
        if (prepareIntent != null) {
            startActivityForResult(call, prepareIntent, "handleVpnPermissionResult");
        } else {
            launchServiceAndAwait(call);
        }
    }

    @ActivityCallback
    private void handleVpnPermissionResult(PluginCall call, ActivityResult result) {
        if (call == null) return;
        if (result.getResultCode() == Activity.RESULT_OK) {
            launchServiceAndAwait(call);
        } else {
            call.reject("Разрешение на создание VPN-подключения отклонено пользователем");
        }
    }

    private void launchServiceAndAwait(PluginCall call) {
        final String configJson = call.getString("configJson", "");
        final String nodeName = call.getString("activeNodeName", "VPN Сервер");
        final String outboundTag = call.getString("outboundTag", "");
        final String dnsServer = call.getString("dnsServer", "1.1.1.1");
        final String excludedCsv = extractStringArrayCsv(call, "excludedPackages");
        final String perAppMode = call.getString("perAppMode", "all");
        final String perAppPackagesCsv = extractStringArrayCsv(call, "perAppPackages");
        final String candidatesJson = call.getString("candidatesJson", "[]");
        final String watchdogJson = call.getString("watchdogJson", "{}");

        ioPool.execute(() -> {
            try {
                Intent serviceIntent = new Intent(getContext(), AegisVpnService.class);
                serviceIntent.setAction(AegisVpnService.ACTION_START);
                serviceIntent.putExtra(AegisVpnService.EXTRA_CONFIG_JSON, configJson);
                serviceIntent.putExtra(AegisVpnService.EXTRA_NODE_NAME, nodeName);
                serviceIntent.putExtra(AegisVpnService.EXTRA_OUTBOUND_TAG, outboundTag);
                serviceIntent.putExtra(AegisVpnService.EXTRA_DNS_SERVER, dnsServer);
                serviceIntent.putExtra(AegisVpnService.EXTRA_EXCLUDED_PACKAGES, excludedCsv);
                serviceIntent.putExtra(AegisVpnService.EXTRA_PER_APP_MODE, perAppMode);
                serviceIntent.putExtra(AegisVpnService.EXTRA_PER_APP_PACKAGES, perAppPackagesCsv);
                serviceIntent.putExtra(AegisVpnService.EXTRA_CANDIDATES_JSON, candidatesJson);
                serviceIntent.putExtra(AegisVpnService.EXTRA_WATCHDOG_JSON, watchdogJson);

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    getContext().startForegroundService(serviceIntent);
                } else {
                    getContext().startService(serviceIntent);
                }

                long deadline = System.currentTimeMillis() + 9500L;
                while (System.currentTimeMillis() < deadline) {
                    Thread.sleep(150);
                    if (AegisVpnService.isVpnRunning()) {
                        JSObject res = new JSObject();
                        res.put("running", true);
                        res.put("activeNodeName", AegisVpnService.getActiveNodeName());
                        call.resolve(res);
                        return;
                    }
                    String err = AegisVpnService.getLastError();
                    if (!AegisVpnService.isVpnStarting() && err != null && !err.isEmpty()) {
                        call.reject(err);
                        return;
                    }
                }

                if (AegisVpnService.isVpnRunning()) {
                    JSObject res = new JSObject();
                    res.put("running", true);
                    res.put("activeNodeName", AegisVpnService.getActiveNodeName());
                    call.resolve(res);
                } else {
                    String err = AegisVpnService.getLastError();
                    call.reject((err != null && !err.isEmpty()) ? err : "Таймаут запуска ядра VPN");
                }
            } catch (Exception e) {
                call.reject("Ошибка запуска VPN-сервиса: " + e.getMessage());
            }
        });
    }

    @PluginMethod
    public void stopVpn(PluginCall call) {
        ioPool.execute(() -> {
            try {
                Intent stopIntent = new Intent(getContext(), AegisVpnService.class);
                stopIntent.setAction(AegisVpnService.ACTION_STOP);
                getContext().startService(stopIntent);
                Thread.sleep(200);
            } catch (Exception ignored) {
            }
            JSObject res = new JSObject();
            res.put("running", false);
            call.resolve(res);
        });
    }

    @PluginMethod
    public void switchOutbound(PluginCall call) {
        final String tag = call.getString("tag", "");
        final String nodeName = call.getString("activeNodeName", "VPN Сервер");
        ioPool.execute(() -> {
            boolean ok = AegisVpnService.switchActiveOutboundHot(tag, nodeName);
            JSObject res = new JSObject();
            res.put("switched", ok);
            res.put("running", AegisVpnService.isVpnRunning());
            res.put("activeNodeName", AegisVpnService.getActiveNodeName());
            call.resolve(res);
        });
    }

    @PluginMethod
    public void switchAiOutbound(PluginCall call) {
        final String tag = call.getString("tag", "");
        final String nodeName = call.getString("activeAiNodeName", "AI Сервер");
        ioPool.execute(() -> {
            boolean ok = AegisVpnService.switchAiOutboundHot(tag, nodeName);
            JSObject res = new JSObject();
            res.put("switched", ok);
            res.put("running", AegisVpnService.isVpnRunning());
            res.put("activeAiNodeName", AegisVpnService.getActiveAiNodeName());
            res.put("activeAiOutboundTag", AegisNativeWatchdog.getActiveAiOutboundTag());
            call.resolve(res);
        });
    }

    @PluginMethod
    public void probeAiNode(PluginCall call) {
        final String tag = call.getString("tag", "");
        final int timeoutMs = call.getInt("timeoutMs", 5200);
        ioPool.execute(() -> {
            org.json.JSONObject raw = AegisNativeWatchdog.probeNodeAiCompatibility(tag, timeoutMs);
            JSObject res = new JSObject();
            res.put("reachable", raw.optBoolean("reachable", false));
            res.put("latencyMs", raw.optInt("latencyMs", 0));
            res.put("exitCountry", raw.optString("exitCountry", ""));
            res.put("googleCountry", raw.optString("googleCountry", ""));
            res.put("geminiStatus", raw.optInt("geminiStatus", 0));
            res.put("geminiLocation", raw.optString("geminiLocation", ""));
            res.put("geminiHtmlAllowed", raw.optString("geminiHtmlAllowed", ""));
            res.put("chatgptStatus", raw.optInt("chatgptStatus", 0));
            res.put("chatgptBlockedBody", raw.optBoolean("chatgptBlockedBody", false));
            res.put("grokStatus", raw.optInt("grokStatus", 0));
            res.put("grokBlockedBody", raw.optBoolean("grokBlockedBody", false));
            res.put("error", raw.optString("error", ""));
            call.resolve(res);
        });
    }

    @PluginMethod
    public void getStatus(PluginCall call) {
        long[] stats = AegisVpnService.getTrafficStats();
        JSObject res = new JSObject();
        res.put("running", AegisVpnService.isVpnRunning());
        res.put("activeNodeName", AegisVpnService.getActiveNodeName());
        res.put("activeAiNodeName", AegisVpnService.getActiveAiNodeName());
        res.put("activeOutboundTag", AegisNativeWatchdog.getActiveOutboundTag());
        res.put("activeAiOutboundTag", AegisNativeWatchdog.getActiveAiOutboundTag());
        res.put("nativeWatchdogActive", AegisNativeWatchdog.isWatchdogActive());
        res.put("nativeSwitchCount", AegisNativeWatchdog.getNativeSwitchCount());
        res.put("lastSwitchFrom", AegisNativeWatchdog.getLastSwitchFrom());
        res.put("lastSwitchTo", AegisNativeWatchdog.getLastSwitchTo());
        res.put("lastSwitchReason", AegisNativeWatchdog.getLastSwitchReason());
        res.put("lastSwitchTimestamp", AegisNativeWatchdog.getLastSwitchTimestamp());
        res.put("lastMeasuredSpeedKbps", AegisNativeWatchdog.getLastMeasuredSpeedKbps());
        res.put("networkType", AegisVpnService.detectActiveNetworkType(getContext()));
        res.put("roamingHandoverCount", AegisVpnService.getRoamingHandoverCount());
        res.put("lastHandoverTimestamp", AegisVpnService.getLastHandoverTimestamp());
        res.put("activeMtu", AegisVpnService.getActiveMtu());
        res.put("bestWifiTag", AegisNativeWatchdog.getBestWifiOutboundTag());
        res.put("bestCellularTag", AegisNativeWatchdog.getBestCellularOutboundTag());
        res.put("lastError", AegisVpnService.getLastError());
        res.put("txPackets", stats[0]);
        res.put("txBytes", stats[1]);
        res.put("rxPackets", stats[2]);
        res.put("rxBytes", stats[3]);
        call.resolve(res);
    }

    @PluginMethod
    public void rebindNetwork(PluginCall call) {
        final String reason = call.getString("reason", "Сброс зависших сокетов и обновление маршрута");
        ioPool.execute(() -> {
            AegisVpnService.closeAllActiveConnectionsHot();
            boolean ok = AegisVpnService.rebindAndRestartSingboxHot(reason, true);
            String netType = AegisVpnService.detectActiveNetworkType(getContext());
            if (ok) {
                AegisNativeWatchdog.onPhysicalNetworkHandover(getContext(), netType, reason);
            }
            JSObject res = new JSObject();
            res.put("rebound", ok);
            res.put("networkType", netType);
            res.put("activeNodeName", AegisVpnService.getActiveNodeName());
            res.put("activeOutboundTag", AegisNativeWatchdog.getActiveOutboundTag());
            call.resolve(res);
        });
    }

    @PluginMethod
    public void tcpPing(PluginCall call) {
        final String host = call.getString("host", "");
        final int port = call.getInt("port", 443);
        final int timeoutMs = call.getInt("timeoutMs", 3200);

        if (host == null || host.trim().isEmpty()) {
            JSObject res = new JSObject();
            res.put("reachable", false);
            res.put("error", "Пустой адрес хоста");
            call.resolve(res);
            return;
        }

        ioPool.execute(() -> {
            long startNs = System.nanoTime();
            try (Socket socket = new Socket()) {
                String cleanHost = host.trim();
                InetAddress targetAddr = null;
                try {
                    Network physNet = AegisVpnService.findActivePhysicalNetwork(getContext());
                    InetAddress[] addrs = (physNet != null)
                            ? physNet.getAllByName(cleanHost)
                            : InetAddress.getAllByName(cleanHost);
                    if (addrs != null) {
                        for (InetAddress a : addrs) {
                            if (a instanceof Inet4Address && !a.isLoopbackAddress()) {
                                targetAddr = a;
                                break;
                            }
                        }
                        if (targetAddr == null && addrs.length > 0) {
                            targetAddr = addrs[0];
                        }
                    }
                } catch (Exception ignored) {
                }

                InetSocketAddress sockAddr = (targetAddr != null)
                        ? new InetSocketAddress(targetAddr, port)
                        : new InetSocketAddress(cleanHost, port);
                socket.connect(sockAddr, timeoutMs);
                long elapsedMs = Math.max(1L, (System.nanoTime() - startNs) / 1_000_000L);
                JSObject res = new JSObject();
                res.put("reachable", true);
                res.put("latencyMs", elapsedMs);
                call.resolve(res);
            } catch (Exception e) {
                JSObject res = new JSObject();
                res.put("reachable", false);
                res.put("error", e.getMessage() != null ? e.getMessage() : "Таймаут соединения");
                call.resolve(res);
            }
        });
    }

    private String extractStringArrayCsv(PluginCall call, String fieldName) {
        StringBuilder sb = new StringBuilder();
        try {
            JSArray arr = call.getArray(fieldName);
            if (arr != null) {
                for (int i = 0; i < arr.length(); i++) {
                    String item = arr.optString(i, "").trim();
                    if (!item.isEmpty()) {
                        if (sb.length() > 0) sb.append(',');
                        sb.append(item);
                    }
                }
                return sb.toString();
            }
        } catch (Exception ignored) {
        }
        String str = call.getString(fieldName, "");
        return str != null ? str.trim() : "";
    }

    @PluginMethod
    public void httpFetch(PluginCall call) {
        final String urlStr = call.getString("url", "");
        final boolean useTunnelProxy = Boolean.TRUE.equals(call.getBoolean("useTunnelProxy", false));
        final int timeoutMs = call.getInt("timeoutMs", 8000);
        final JSObject customHeaders = call.getObject("headers");

        if (urlStr == null || (!urlStr.startsWith("http://") && !urlStr.startsWith("https://"))) {
            call.reject("Некорректный HTTP/HTTPS URL");
            return;
        }

        ioPool.execute(() -> {
            HttpURLConnection conn = null;
            try {
                URL url = new URL(urlStr);
                if (useTunnelProxy && AegisVpnService.isVpnRunning()) {
                    Proxy proxy = new Proxy(
                            Proxy.Type.HTTP,
                            new InetSocketAddress("127.0.0.1", AegisVpnService.LOCAL_MIXED_PORT)
                    );
                    conn = (HttpURLConnection) url.openConnection(proxy);
                } else {
                    conn = (HttpURLConnection) url.openConnection();
                }
                conn.setRequestMethod("GET");
                conn.setInstanceFollowRedirects(true);
                conn.setConnectTimeout(timeoutMs);
                conn.setReadTimeout(timeoutMs);
                conn.setRequestProperty("User-Agent", "Shadowrocket/2075 CFNetwork/1568.200.51 Darwin/24.1.0");

                if (customHeaders != null) {
                    Iterator<String> keys = customHeaders.keys();
                    while (keys.hasNext()) {
                        String key = keys.next();
                        if (key != null && !key.trim().isEmpty()) {
                            String val = customHeaders.optString(key, "");
                            if (val != null && !val.isEmpty()) {
                                conn.setRequestProperty(key.trim(), val);
                            }
                        }
                    }
                }

                int status = conn.getResponseCode();
                InputStream stream = (status >= 200 && status < 400)
                        ? conn.getInputStream()
                        : conn.getErrorStream();

                StringBuilder sb = new StringBuilder();
                if (stream != null) {
                    try (BufferedReader reader = new BufferedReader(
                            new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            sb.append(line).append('\n');
                        }
                    }
                }

                JSObject respHeaders = new JSObject();
                Map<String, List<String>> headerFields = conn.getHeaderFields();
                if (headerFields != null) {
                    for (Map.Entry<String, List<String>> entry : headerFields.entrySet()) {
                        String k = entry.getKey();
                        List<String> vals = entry.getValue();
                        if (k != null && vals != null && !vals.isEmpty()) {
                            String joined = String.join(", ", vals);
                            respHeaders.put(k.toLowerCase(Locale.ROOT), joined);
                        }
                    }
                }

                JSObject res = new JSObject();
                res.put("status", status);
                res.put("body", sb.toString());
                res.put("headers", respHeaders);
                call.resolve(res);
            } catch (Exception e) {
                call.reject("Ошибка сетевого запроса: " + e.getMessage());
            } finally {
                if (conn != null) {
                    conn.disconnect();
                }
            }
        });
    }

    @PluginMethod
    public void probeProxyDelay(PluginCall call) {
        final String tag = call.getString("tag", "proxy-active");
        final int timeoutMs = call.getInt("timeoutMs", 4000);
        ioPool.execute(() -> {
            int delay = AegisVpnService.probeOutboundDelay(tag, timeoutMs);
            JSObject res = new JSObject();
            res.put("reachable", delay > 0);
            if (delay > 0) {
                res.put("delayMs", delay);
            }
            call.resolve(res);
        });
    }

    @PluginMethod
    public void scanLocalPorts(PluginCall call) {
        final int timeoutMs = Math.max(120, Math.min(call.getInt("timeoutMs", 260), 2000));
        final List<Integer> portsToScan = new ArrayList<>();
        try {
            JSArray arr = call.getArray("ports");
            if (arr != null) {
                for (int i = 0; i < arr.length(); i++) {
                    int p = arr.optInt(i, -1);
                    if (p > 0 && p <= 65535) {
                        portsToScan.add(p);
                    }
                }
            }
        } catch (Exception ignored) {
        }
        if (portsToScan.isEmpty()) {
            int[] defaults = new int[]{10808, 2080, 7890, 12334, 1080, 9050};
            for (int p : defaults) portsToScan.add(p);
        }

        ioPool.execute(() -> {
            List<Callable<JSObject>> tasks = new ArrayList<>();
            for (final int port : portsToScan) {
                tasks.add(() -> {
                    JSObject item = new JSObject();
                    item.put("port", port);
                    long t0 = System.nanoTime();
                    try (Socket s = new Socket()) {
                        s.connect(new InetSocketAddress("127.0.0.1", port), timeoutMs);
                        long ms = Math.max(1L, (System.nanoTime() - t0) / 1_000_000L);
                        item.put("open", true);
                        item.put("latencyMs", ms);
                    } catch (Exception ignored) {
                        item.put("open", false);
                    }
                    return item;
                });
            }
            JSArray results = new JSArray();
            try {
                List<Future<JSObject>> futures = ioPool.invokeAll(tasks);
                for (Future<JSObject> f : futures) {
                    results.put(f.get());
                }
            } catch (Exception ignored) {
            }
            JSObject res = new JSObject();
            res.put("results", results);
            call.resolve(res);
        });
    }

    @PluginMethod
    public void listInstalledVpnApps(PluginCall call) {
        ioPool.execute(() -> {
            JSArray apps = new JSArray();
            try {
                PackageManager pm = getContext().getPackageManager();
                String selfPkg = getContext().getPackageName();
                Intent vpnIntent = new Intent("android.net.VpnService");
                List<ResolveInfo> services = pm.queryIntentServices(vpnIntent, 0);
                Set<String> seen = new HashSet<>();
                if (services != null) {
                    for (ResolveInfo ri : services) {
                        if (ri.serviceInfo == null || ri.serviceInfo.packageName == null) continue;
                        String pkg = ri.serviceInfo.packageName;
                        if (pkg.equals(selfPkg) || seen.contains(pkg)) continue;
                        if (pm.getLaunchIntentForPackage(pkg) == null) continue;
                        seen.add(pkg);
                        String label = pkg;
                        try {
                            ApplicationInfo ai = ri.serviceInfo.applicationInfo;
                            if (ai != null) {
                                CharSequence cs = pm.getApplicationLabel(ai);
                                if (cs != null && cs.length() > 0) {
                                    label = cs.toString();
                                }
                            }
                        } catch (Exception ignored) {
                        }
                        JSObject appObj = new JSObject();
                        appObj.put("packageName", pkg);
                        appObj.put("appName", label);
                        apps.put(appObj);
                    }
                }
            } catch (Exception ignored) {
            }
            JSObject res = new JSObject();
            res.put("apps", apps);
            call.resolve(res);
        });
    }

    @PluginMethod
    public void launchApp(PluginCall call) {
        final String pkg = call.getString("packageName", "");
        if (pkg == null || pkg.trim().isEmpty()) {
            call.reject("Не указано имя пакета VPN-приложения");
            return;
        }
        try {
            PackageManager pm = getContext().getPackageManager();
            Intent launch = pm.getLaunchIntentForPackage(pkg.trim());
            if (launch == null) {
                call.reject("Приложение " + pkg + " не найдено на устройстве");
                return;
            }
            launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            getContext().startActivity(launch);
            JSObject res = new JSObject();
            res.put("launched", true);
            call.resolve(res);
        } catch (Exception e) {
            call.reject("Не удалось открыть приложение: " + e.getMessage());
        }
    }

    @PluginMethod
    public void updateWatchdogConfig(PluginCall call) {
        final String candidatesJson = call.getString("candidatesJson", "");
        final String watchdogJson = call.getString("watchdogJson", "");
        AegisNativeWatchdog.updateCandidatesAndSettings(candidatesJson, watchdogJson);
        JSObject res = new JSObject();
        res.put("updated", true);
        call.resolve(res);
    }

    @PluginMethod
    public void measureTunnelSpeed(PluginCall call) {
        final int bytesToFetch = call.getInt("bytes", 147456);
        final int timeoutMs = call.getInt("timeoutMs", 4500);
        ioPool.execute(() -> {
            int kbps = AegisNativeWatchdog.measureTunnelBandwidthKbps(bytesToFetch, timeoutMs);
            JSObject res = new JSObject();
            res.put("ok", kbps > 0);
            res.put("kbps", Math.max(0, kbps));
            call.resolve(res);
        });
    }

    @PluginMethod
    public void listInstalledApps(PluginCall call) {
        ioPool.execute(() -> {
            List<JSObject> found = new ArrayList<>();
            try {
                PackageManager pm = getContext().getPackageManager();
                String selfPkg = getContext().getPackageName();
                Intent mainIntent = new Intent(Intent.ACTION_MAIN, null);
                mainIntent.addCategory(Intent.CATEGORY_LAUNCHER);
                List<ResolveInfo> resolved = pm.queryIntentActivities(mainIntent, 0);
                Set<String> seen = new HashSet<>();
                if (resolved != null) {
                    for (ResolveInfo ri : resolved) {
                        if (ri.activityInfo == null || ri.activityInfo.packageName == null) continue;
                        String pkg = ri.activityInfo.packageName;
                        if (pkg.equals(selfPkg) || seen.contains(pkg)) continue;
                        seen.add(pkg);
                        String label = pkg;
                        try {
                            CharSequence cs = ri.loadLabel(pm);
                            if (cs != null && cs.length() > 0) {
                                label = cs.toString().trim();
                            }
                        } catch (Exception ignored) {
                        }
                        JSObject obj = new JSObject();
                        obj.put("packageName", pkg);
                        obj.put("appName", label);
                        found.add(obj);
                    }
                }
                Collections.sort(found, new Comparator<JSObject>() {
                    @Override
                    public int compare(JSObject a, JSObject b) {
                        return a.optString("appName", "").compareToIgnoreCase(b.optString("appName", ""));
                    }
                });
            } catch (Exception ignored) {
            }
            JSArray arr = new JSArray();
            for (JSObject item : found) {
                arr.put(item);
            }
            JSObject res = new JSObject();
            res.put("apps", arr);
            call.resolve(res);
        });
    }
}
