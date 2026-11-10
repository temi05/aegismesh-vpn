package com.aegismesh.vpn;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

/**
 * Нативный фоновый сторож 24/7 и движок параллельной гонки Умной Автозамены v3.2.
 * Работает внутри Foreground-сервиса Android даже при выключенном экране и свёрнутом приложении.
 */
public class AegisNativeWatchdog {
    private static final String SAVED_SESSION_FILE = "aegis-last-session.json";
    private static final ExecutorService racePool = Executors.newFixedThreadPool(12);

    private static final Pattern GOOGLE_SW_PRIMARY = Pattern.compile(
            "\\[\"yt\\.sw\\.adr\"\\s*,\\s*null\\s*,\\s*\\[\\[\\[\\s*\"[a-zA-Z-]+\"\\s*,\\s*\"([A-Z]{2})\""
    );
    private static final Pattern GOOGLE_SW_FALLBACK = Pattern.compile(
            "\\[\\[\\[\\s*\"[a-z]{2,3}(?:-[A-Za-z]{2,4})?\"\\s*,\\s*\"([A-Z]{2})\"\\s*,\\s*null\\s*,\\s*\"[0-9a-fA-F.:]+\""
    );
    private static final Pattern GOOGLE_WIZ_ISO3 = Pattern.compile(",\\s*null\\s*,\\s*\"([A-Z]{3})\"");
    private static final Map<String, String> GOOGLE_ISO3_MAP = createGoogleIso3Map();

    private static Map<String, String> createGoogleIso3Map() {
        Map<String, String> m = new HashMap<>();
        String[][] pairs = new String[][]{
                {"RUS", "RU"}, {"BLR", "BY"}, {"CHN", "CN"}, {"HKG", "HK"}, {"MAC", "MO"},
                {"IRN", "IR"}, {"PRK", "KP"}, {"CUB", "CU"}, {"SYR", "SY"}, {"USA", "US"},
                {"NLD", "NL"}, {"DEU", "DE"}, {"FIN", "FI"}, {"SWE", "SE"}, {"GBR", "GB"},
                {"FRA", "FR"}, {"POL", "PL"}, {"CHE", "CH"}, {"AUT", "AT"}, {"CZE", "CZ"},
                {"EST", "EE"}, {"LVA", "LV"}, {"LTU", "LT"}, {"NOR", "NO"}, {"DNK", "DK"},
                {"IRL", "IE"}, {"ESP", "ES"}, {"ITA", "IT"}, {"CAN", "CA"}, {"JPN", "JP"},
                {"SGP", "SG"}, {"KOR", "KR"}, {"TUR", "TR"}, {"KAZ", "KZ"}, {"ARE", "AE"},
                {"IND", "IN"}, {"BRA", "BR"}, {"AUS", "AU"}
        };
        for (String[] p : pairs) {
            m.put(p[0], p[1]);
        }
        return m;
    }

    private static volatile Thread sWatchdogThread = null;
    private static volatile boolean sWatchdogRunning = false;
    private static volatile String sActiveOutboundTag = "";
    private static volatile String sActiveAiOutboundTag = "";
    private static volatile String sCandidatesJson = "[]";
    private static volatile String sWatchdogJson = "{}";
    private static final Object AI_PROBE_LOCK = new Object();

    private static volatile int sNativeSwitchCount = 0;
    private static volatile String sLastSwitchFrom = "";
    private static volatile String sLastSwitchTo = "";
    private static volatile String sLastSwitchReason = "";
    private static volatile long sLastSwitchTimestamp = 0L;
    private static volatile int sLastMeasuredSpeedKbps = -1;
    private static volatile String sBestWifiOutboundTag = "";
    private static volatile String sBestCellularOutboundTag = "";

    public static String getBestWifiOutboundTag() {
        return sBestWifiOutboundTag;
    }

    public static String getBestCellularOutboundTag() {
        return sBestCellularOutboundTag;
    }

    private static void syncRememberedTagsFromWatchdogJson(String watchdogJson) {
        if (watchdogJson == null || watchdogJson.isEmpty()) return;
        try {
            JSONObject cfg = new JSONObject(watchdogJson);
            String bw = cfg.optString("bestWifiTag", "").trim();
            String bc = cfg.optString("bestCellularTag", "").trim();
            if (!bw.isEmpty()) sBestWifiOutboundTag = bw;
            if (!bc.isEmpty()) sBestCellularOutboundTag = bc;
        } catch (Exception ignored) {
        }
    }

    private static void rememberSuccessfulNetworkTag(Context ctx, String tag) {
        if (tag == null || tag.isEmpty()) return;
        String netType = AegisVpnService.detectActiveNetworkType(ctx);
        if ("cellular".equals(netType)) {
            sBestCellularOutboundTag = tag;
        } else if ("wifi".equals(netType) || "ethernet".equals(netType)) {
            sBestWifiOutboundTag = tag;
        }
    }

    public static String getActiveOutboundTag() {
        return sActiveOutboundTag;
    }

    public static void setActiveOutboundTag(String tag) {
        sActiveOutboundTag = tag != null ? tag : "";
    }

    public static String getActiveAiOutboundTag() {
        return sActiveAiOutboundTag;
    }

    public static void setActiveAiOutboundTag(String tag) {
        sActiveAiOutboundTag = tag != null ? tag : "";
    }

    public static boolean isWatchdogActive() {
        return sWatchdogRunning;
    }

    public static int getNativeSwitchCount() {
        return sNativeSwitchCount;
    }

    public static String getLastSwitchFrom() {
        return sLastSwitchFrom;
    }

    public static String getLastSwitchTo() {
        return sLastSwitchTo;
    }

    public static String getLastSwitchReason() {
        return sLastSwitchReason;
    }

    public static long getLastSwitchTimestamp() {
        return sLastSwitchTimestamp;
    }

    public static int getLastMeasuredSpeedKbps() {
        return sLastMeasuredSpeedKbps;
    }

    public static boolean hasSavedSession(Context ctx) {
        if (ctx == null) return false;
        File f = new File(ctx.getFilesDir(), SAVED_SESSION_FILE);
        return f.exists() && f.length() > 20;
    }

    public static void saveSession(
            Context ctx,
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
        if (ctx == null || configJson == null || configJson.trim().isEmpty()) return;
        try {
            JSONObject obj = new JSONObject();
            obj.put("configJson", configJson);
            obj.put("nodeName", nodeName != null ? nodeName : "Каскад AegisMesh");
            obj.put("outboundTag", outboundTag != null ? outboundTag : "");
            obj.put("dnsServer", dnsServer != null ? dnsServer : "1.1.1.1");
            obj.put("excludedPackages", excludedPackages != null ? excludedPackages : "");
            obj.put("perAppMode", perAppMode != null ? perAppMode : "all");
            obj.put("perAppPackages", perAppPackages != null ? perAppPackages : "");
            obj.put("candidatesJson", candidatesJson != null ? candidatesJson : "[]");
            obj.put("watchdogJson", watchdogJson != null ? watchdogJson : "{}");

            File f = new File(ctx.getFilesDir(), SAVED_SESSION_FILE);
            try (FileOutputStream fos = new FileOutputStream(f, false)) {
                fos.write(obj.toString().getBytes(StandardCharsets.UTF_8));
                fos.flush();
            }
        } catch (Exception ignored) {
        }
    }

    public static JSONObject loadSession(Context ctx) {
        if (ctx == null) return null;
        try {
            File f = new File(ctx.getFilesDir(), SAVED_SESSION_FILE);
            if (!f.exists()) return null;
            byte[] buf = new byte[(int) f.length()];
            try (FileInputStream fis = new FileInputStream(f)) {
                int read = fis.read(buf);
                if (read <= 0) return null;
            }
            return new JSONObject(new String(buf, StandardCharsets.UTF_8));
        } catch (Exception ignored) {
            return null;
        }
    }

    public static void updateSavedActiveNode(Context ctx, String outboundTag, String nodeName) {
        if (ctx == null || outboundTag == null || outboundTag.isEmpty()) return;
        try {
            JSONObject saved = loadSession(ctx);
            if (saved == null) return;
            saved.put("outboundTag", outboundTag);
            if (nodeName != null && !nodeName.isEmpty()) {
                saved.put("nodeName", nodeName);
            }
            File f = new File(ctx.getFilesDir(), SAVED_SESSION_FILE);
            try (FileOutputStream fos = new FileOutputStream(f, false)) {
                fos.write(saved.toString().getBytes(StandardCharsets.UTF_8));
                fos.flush();
            }
        } catch (Exception ignored) {
        }
    }

    public static int probeOutboundFast1500(String outboundTag, int timeoutMs) {
        int budget = Math.max(900, Math.min(timeoutMs, 1550));
        return probeSingleUrl(outboundTag, "http://connectivitycheck.gstatic.com/generate_204", budget);
    }

    /**
     * Тройная сквозная проверка задержки туннеля (Android gstatic 204 -> www.gstatic 204 -> Cloudflare 204).
     * Первым проверяется connectivitycheck.gstatic.com/generate_204, который никогда не блокируется ТСПУ на мобильных операторах РФ!
     */
    public static int probeOutboundMultiTarget(String outboundTag, int timeoutMs) {
        int primaryBudget = Math.max(1200, Math.min(timeoutMs, 2400));
        int primary = probeSingleUrl(outboundTag, "http://connectivitycheck.gstatic.com/generate_204", primaryBudget);
        if (primary > 0) return primary;

        int secondaryBudget = Math.max(1100, Math.min(timeoutMs, 2000));
        int secondary = probeSingleUrl(outboundTag, "http://www.gstatic.com/generate_204", secondaryBudget);
        if (secondary > 0) return secondary;

        return probeSingleUrl(outboundTag, "http://cp.cloudflare.com/generate_204", secondaryBudget);
    }

    private static int probeSingleUrl(String outboundTag, String targetUrl, int timeoutMs) {
        if (outboundTag == null || outboundTag.trim().isEmpty()) return -1;
        HttpURLConnection conn = null;
        try {
            int safeTimeout = Math.max(800, Math.min(timeoutMs, 10000));
            String encTag = URLEncoder.encode(outboundTag.trim(), "UTF-8").replace("+", "%20");
            String encTarget = URLEncoder.encode(targetUrl, "UTF-8");
            String probeUrl = "http://127.0.0.1:" + AegisVpnService.CLASH_API_PORT
                    + "/proxies/" + encTag
                    + "/delay?url=" + encTarget + "&timeout=" + safeTimeout;
            conn = (HttpURLConnection) new URL(probeUrl).openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(1500);
            conn.setReadTimeout(safeTimeout + 700);
            int code = conn.getResponseCode();
            if (code >= 200 && code < 300) {
                InputStream is = conn.getInputStream();
                if (is != null) {
                    StringBuilder sb = new StringBuilder();
                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                        String line;
                        while ((line = reader.readLine()) != null) sb.append(line);
                    }
                    int delay = new JSONObject(sb.toString()).optInt("delay", -1);
                    if (delay > 0) return delay;
                }
            }
        } catch (Exception ignored) {
        } finally {
            if (conn != null) conn.disconnect();
        }
        return -1;
    }

    private static String readLimitedBody(HttpURLConnection conn, int statusCode, int maxChars) {
        if (conn == null || maxChars <= 0) return "";
        InputStream rawStream = null;
        try {
            rawStream = (statusCode >= 200 && statusCode < 400)
                    ? conn.getInputStream()
                    : conn.getErrorStream();
            if (rawStream == null) return "";
            String enc = conn.getContentEncoding();
            InputStream decoded = (enc != null && enc.toLowerCase(Locale.ROOT).contains("gzip"))
                    ? new GZIPInputStream(rawStream)
                    : rawStream;
            StringBuilder sb = new StringBuilder();
            char[] buf = new char[4096];
            try (InputStreamReader reader = new InputStreamReader(decoded, StandardCharsets.UTF_8)) {
                int read;
                while ((read = reader.read(buf)) != -1) {
                    int remain = maxChars - sb.length();
                    if (remain <= 0) break;
                    sb.append(buf, 0, Math.min(read, remain));
                    if (sb.length() >= maxChars) break;
                }
            }
            return sb.toString();
        } catch (Exception ignored) {
            return "";
        }
    }

    private static String extractGoogleSwCountry(String swBody) {
        if (swBody == null || swBody.isEmpty()) return "";
        Matcher m1 = GOOGLE_SW_PRIMARY.matcher(swBody);
        if (m1.find()) {
            return m1.group(1).toUpperCase(Locale.ROOT);
        }
        Matcher m2 = GOOGLE_SW_FALLBACK.matcher(swBody);
        if (m2.find()) {
            return m2.group(1).toUpperCase(Locale.ROOT);
        }
        return "";
    }

    private static String extractGoogleWizCountry(String html) {
        if (html == null || html.isEmpty()) return "";
        Matcher m = GOOGLE_WIZ_ISO3.matcher(html);
        while (m.find()) {
            String iso3 = m.group(1);
            String mapped = GOOGLE_ISO3_MAP.get(iso3);
            if (mapped != null) {
                return mapped;
            }
        }
        return "";
    }

    /**
     * Глубокий фоновый изолированный тест VPN-узла v3.2 на реальную совместимость с Google Gemini, ChatGPT и Grok
     * через выделенный порт `127.0.0.1:20809` (`ai-probe-in` -> `proxy-ai-probe`) без влияния на активный трафик пользователя.
     * Проверяет ИСТИННЫЙ регион IP во внутренней базе Google (`sw.js_data` + `WIZ_global_data` + флаг `45631641`),
     * отсекая серверы «NL/FI без рекламы YouTube», которые база Google считает Россией (`RU`)!
     */
    public static JSONObject probeNodeAiCompatibility(String outboundTag, int timeoutMs) {
        JSONObject result = new JSONObject();
        try {
            if (!AegisVpnService.isVpnRunning() || outboundTag == null || outboundTag.trim().isEmpty()) {
                result.put("reachable", false);
                result.put("error", "VPN-сервис не запущен");
                return result;
            }

            int safeTimeout = Math.max(2200, Math.min(timeoutMs, 8500));
            int baseDelay = probeOutboundMultiTarget(outboundTag, Math.min(safeTimeout, 3400));
            if (baseDelay <= 0) {
                result.put("reachable", false);
                result.put("error", "Узел не отвечает на сквозной тест");
                return result;
            }

            synchronized (AI_PROBE_LOCK) {
                boolean switched = AegisVpnService.switchSelectorGroupHot("proxy-ai-probe", outboundTag.trim());
                if (!switched) {
                    result.put("reachable", false);
                    result.put("error", "Селектор proxy-ai-probe недоступен");
                    return result;
                }

                final Proxy aiProbeProxy = new Proxy(
                        Proxy.Type.HTTP,
                        new InetSocketAddress("127.0.0.1", AegisVpnService.LOCAL_AI_PROBE_PORT)
                );
                final int reqTimeout = Math.min(safeTimeout, 4800);
                final String browserUa = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36";

                List<Callable<JSONObject>> checks = new ArrayList<>();

                // 1. Истинный GeoIP во внутренней базе Google GFE (2.8 КБ sw.js_data — точно выявляет "RU" на российских VPS в NL/FI!)
                checks.add(() -> {
                    JSONObject gGeo = new JSONObject();
                    gGeo.put("kind", "google_geo");
                    HttpURLConnection conn = null;
                    try {
                        conn = (HttpURLConnection) new URL("https://www.youtube.com/sw.js_data").openConnection(aiProbeProxy);
                        conn.setRequestMethod("GET");
                        conn.setInstanceFollowRedirects(true);
                        conn.setConnectTimeout(Math.min(3400, reqTimeout));
                        conn.setReadTimeout(Math.min(3400, reqTimeout));
                        conn.setRequestProperty("User-Agent", browserUa);
                        conn.setRequestProperty("Accept-Language", "en-US,en;q=0.9");
                        conn.setRequestProperty("Connection", "close");
                        int code = conn.getResponseCode();
                        if (code >= 200 && code < 300) {
                            String body = readLimitedBody(conn, code, 8192);
                            String swCountry = extractGoogleSwCountry(body);
                            gGeo.put("googleCountry", swCountry);
                        }
                    } catch (Exception ignored) {
                    } finally {
                        if (conn != null) conn.disconnect();
                    }
                    return gGeo;
                });

                // 2. Глубокая проверка страницы Google Gemini (до 3 шагов редиректа + чтение HTML WIZ_global_data и флага 45631641)
                checks.add(() -> {
                    JSONObject g = new JSONObject();
                    g.put("kind", "gemini");
                    String currentUrl = "https://gemini.google.com/app";
                    int lastCode = 0;
                    String lastLoc = "";
                    String htmlAllowed = "";
                    String wizCountry = "";

                    for (int hop = 0; hop < 3; hop++) {
                        HttpURLConnection conn = null;
                        try {
                            URL u = new URL(currentUrl);
                            conn = (HttpURLConnection) u.openConnection(aiProbeProxy);
                            conn.setRequestMethod("GET");
                            conn.setInstanceFollowRedirects(false);
                            conn.setConnectTimeout(reqTimeout);
                            conn.setReadTimeout(reqTimeout);
                            conn.setRequestProperty("User-Agent", browserUa);
                            conn.setRequestProperty("Accept-Language", "en-US,en;q=0.9");
                            conn.setRequestProperty("Connection", "close");
                            lastCode = conn.getResponseCode();
                            String loc = conn.getHeaderField("Location");
                            if (loc != null && !loc.isEmpty()) {
                                lastLoc = loc;
                                String locLower = loc.toLowerCase(Locale.ROOT);
                                if (locLower.contains("/sorry/")
                                        || locLower.contains("faq")
                                        || locLower.contains("unsupported")
                                        || locLower.contains("unavailable")) {
                                    htmlAllowed = "false";
                                    break;
                                }
                                if (lastCode >= 300 && lastCode < 400) {
                                    currentUrl = new URL(u, loc).toString();
                                    continue;
                                }
                            }

                            if (lastCode >= 200 && lastCode < 300) {
                                String html = readLimitedBody(conn, lastCode, 150000);
                                wizCountry = extractGoogleWizCountry(html);
                                String lowerHtml = html.toLowerCase(Locale.ROOT);
                                if (html.contains("\"45631641\":false")
                                        || html.contains("45631641,null,false")
                                        || lowerHtml.contains("gemini isn't currently supported")
                                        || lowerHtml.contains("not currently supported in your country")
                                        || lowerHtml.contains("не поддерживается в вашей стране")) {
                                    htmlAllowed = "false";
                                } else if (html.contains("\"45631641\":true")
                                        || html.contains("45631641,null,true")) {
                                    htmlAllowed = "true";
                                }
                            }
                            break;
                        } catch (Exception e) {
                            break;
                        } finally {
                            if (conn != null) conn.disconnect();
                        }
                    }

                    g.put("status", lastCode);
                    g.put("location", lastLoc);
                    g.put("htmlAllowed", htmlAllowed);
                    g.put("wizCountry", wizCountry);
                    return g;
                });

                // 3. Проверка ChatGPT (Cloudflare trace + чтение JSON-ответа мобильного API OpenAI на unsupported_country)
                checks.add(() -> {
                    JSONObject c = new JSONObject();
                    c.put("kind", "chatgpt");
                    HttpURLConnection conn = null;
                    try {
                        conn = (HttpURLConnection) new URL("https://chatgpt.com/cdn-cgi/trace").openConnection(aiProbeProxy);
                        conn.setRequestMethod("GET");
                        conn.setInstanceFollowRedirects(false);
                        conn.setConnectTimeout(reqTimeout);
                        conn.setReadTimeout(reqTimeout);
                        conn.setRequestProperty("User-Agent", browserUa);
                        conn.setRequestProperty("Connection", "close");
                        int code = conn.getResponseCode();
                        String locCountry = "";
                        if (code >= 200 && code < 300) {
                            String traceBody = readLimitedBody(conn, code, 2048);
                            for (String line : traceBody.split("\n")) {
                                if (line.startsWith("loc=")) {
                                    locCountry = line.substring(4).trim().toUpperCase(Locale.ROOT);
                                    break;
                                }
                            }
                        }
                        conn.disconnect();
                        conn = null;

                        int finalStatus = code;
                        boolean blockedBody = false;
                        if (code >= 200 && code < 300) {
                            HttpURLConnection apiConn = null;
                            try {
                                apiConn = (HttpURLConnection) new URL("https://ios.chat.openai.com/public-api/mobile/server_status/v1").openConnection(aiProbeProxy);
                                apiConn.setRequestMethod("GET");
                                apiConn.setConnectTimeout(Math.min(2800, reqTimeout));
                                apiConn.setReadTimeout(Math.min(2800, reqTimeout));
                                apiConn.setRequestProperty("User-Agent", browserUa);
                                apiConn.setRequestProperty("Connection", "close");
                                int apiCode = apiConn.getResponseCode();
                                String apiBody = readLimitedBody(apiConn, apiCode, 8192).toLowerCase(Locale.ROOT);
                                if (apiCode == 403 || apiCode == 429) {
                                    finalStatus = apiCode;
                                    blockedBody = true;
                                } else if (apiBody.contains("unsupported_country")
                                        || apiBody.contains("vpn_disallowed")
                                        || apiBody.contains("access denied")) {
                                    finalStatus = 403;
                                    blockedBody = true;
                                } else if (apiCode >= 200 && apiCode < 300) {
                                    finalStatus = apiCode;
                                }
                            } catch (Exception ignored) {
                            } finally {
                                if (apiConn != null) apiConn.disconnect();
                            }
                        }

                        c.put("status", finalStatus);
                        c.put("country", locCountry);
                        c.put("blockedBody", blockedBody);
                    } catch (Exception e) {
                        c.put("status", 0);
                    } finally {
                        if (conn != null) conn.disconnect();
                    }
                    return c;
                });

                // 4. Реальная проверка главной страницы Grok (xAI), а не только /cdn-cgi/trace
                checks.add(() -> {
                    JSONObject x = new JSONObject();
                    x.put("kind", "grok");
                    HttpURLConnection conn = null;
                    try {
                        conn = (HttpURLConnection) new URL("https://grok.com/").openConnection(aiProbeProxy);
                        conn.setRequestMethod("GET");
                        conn.setInstanceFollowRedirects(false);
                        conn.setConnectTimeout(reqTimeout);
                        conn.setReadTimeout(reqTimeout);
                        conn.setRequestProperty("User-Agent", browserUa);
                        conn.setRequestProperty("Connection", "close");
                        int code = conn.getResponseCode();
                        boolean blockedBody = (code == 403);
                        if (code >= 200 && code < 300) {
                            String body = readLimitedBody(conn, code, 16384).toLowerCase(Locale.ROOT);
                            if (body.contains("not available in your region")
                                    || body.contains("unsupported country")) {
                                blockedBody = true;
                            }
                        }
                        x.put("status", code);
                        x.put("blockedBody", blockedBody);
                    } catch (Exception e) {
                        x.put("status", 0);
                    } finally {
                        if (conn != null) conn.disconnect();
                    }
                    return x;
                });

                List<Future<JSONObject>> futures = racePool.invokeAll(checks, safeTimeout + 1200L, TimeUnit.MILLISECONDS);
                int geminiStatus = 0;
                String geminiLocation = "";
                String geminiHtmlAllowed = "";
                String googleSwCountry = "";
                String googleWizCountry = "";
                int chatgptStatus = 0;
                boolean chatgptBlockedBody = false;
                int grokStatus = 0;
                boolean grokBlockedBody = false;
                String exitCountry = "";

                for (Future<JSONObject> f : futures) {
                    if (f.isDone() && !f.isCancelled()) {
                        try {
                            JSONObject r = f.get();
                            String kind = r.optString("kind", "");
                            if ("google_geo".equals(kind)) {
                                googleSwCountry = r.optString("googleCountry", "");
                            } else if ("gemini".equals(kind)) {
                                geminiStatus = r.optInt("status", 0);
                                geminiLocation = r.optString("location", "");
                                geminiHtmlAllowed = r.optString("htmlAllowed", "");
                                googleWizCountry = r.optString("wizCountry", "");
                            } else if ("chatgpt".equals(kind)) {
                                chatgptStatus = r.optInt("status", 0);
                                chatgptBlockedBody = r.optBoolean("blockedBody", false);
                                String cc = r.optString("country", "");
                                if (!cc.isEmpty()) exitCountry = cc;
                            } else if ("grok".equals(kind)) {
                                grokStatus = r.optInt("status", 0);
                                grokBlockedBody = r.optBoolean("blockedBody", false);
                            }
                        } catch (Exception ignored) {
                        }
                    }
                }

                String finalGoogleCountry = !googleSwCountry.isEmpty() ? googleSwCountry : googleWizCountry;

                result.put("reachable", true);
                result.put("latencyMs", baseDelay);
                result.put("exitCountry", exitCountry);
                result.put("googleCountry", finalGoogleCountry);
                result.put("geminiStatus", geminiStatus);
                result.put("geminiLocation", geminiLocation);
                result.put("geminiHtmlAllowed", geminiHtmlAllowed);
                result.put("chatgptStatus", chatgptStatus);
                result.put("chatgptBlockedBody", chatgptBlockedBody);
                result.put("grokStatus", grokStatus);
                result.put("grokBlockedBody", grokBlockedBody);
            }
        } catch (Exception e) {
            try {
                result.put("reachable", false);
                result.put("error", e.getMessage() != null ? e.getMessage() : "Ошибка ИИ-теста");
            } catch (Exception ignored) {
            }
        }
        return result;
    }

    /**
     * Реальный микро-замер пропускной способности активного VPN-туннеля в Кбит/с через локальный порт sing-box.
     */
    public static int measureTunnelBandwidthKbps(int bytesToFetch, int timeoutMs) {
        if (!AegisVpnService.isVpnRunning()) return -1;
        int safeBytes = Math.max(32768, Math.min(bytesToFetch, 524288));
        String[] urls = new String[]{
                "https://speed.cloudflare.com/__down?bytes=" + safeBytes,
                "https://www.gstatic.com/webp/gallery/1.jpg"
        };

        for (String testUrl : urls) {
            HttpURLConnection conn = null;
            try {
                Proxy proxy = new Proxy(
                        Proxy.Type.HTTP,
                        new InetSocketAddress("127.0.0.1", AegisVpnService.LOCAL_MIXED_PORT)
                );
                long t0 = System.nanoTime();
                conn = (HttpURLConnection) new URL(testUrl).openConnection(proxy);
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(Math.min(timeoutMs, 3000));
                conn.setReadTimeout(timeoutMs);
                conn.setUseCaches(false);
                int status = conn.getResponseCode();
                if (status >= 200 && status < 300) {
                    InputStream is = conn.getInputStream();
                    if (is != null) {
                        byte[] buf = new byte[8192];
                        long totalRead = 0L;
                        int r;
                        while ((r = is.read(buf)) != -1) {
                            totalRead += r;
                            if (totalRead >= safeBytes) break;
                        }
                        is.close();
                        long elapsedMs = Math.max(15L, (System.nanoTime() - t0) / 1_000_000L);
                        if (totalRead >= 8192L) {
                            int kbps = (int) ((totalRead * 8L * 1000L) / (elapsedMs * 1000L));
                            sLastMeasuredSpeedKbps = Math.max(1, kbps);
                            return sLastMeasuredSpeedKbps;
                        }
                    }
                }
            } catch (Exception ignored) {
            } finally {
                if (conn != null) conn.disconnect();
            }
        }
        return -1;
    }

    /**
     * Многоволновая параллельная гонка резервов (Parallel Hedged Race v3.3 для мобильного интернета LTE и Wi-Fi):
     * 1) На мобильной сети в первую очередь тестирует серверы с пометками LTE / 4G / через РФ / Обход / Reality.
     * 2) Если 1-я волна (6 серверов) не ответила — тестирует 2-ю волну (следующие 8 серверов).
     * 3) Если ни один сервер не ответил (залипли сокеты после смены Wi-Fi ↔ LTE) — перезапускает процесс sing-box на новом интерфейсе и повторяет гонку!
     */
    public static synchronized boolean raceAndSwitchBestCandidate(Context ctx, String reasonPrefix) {
        if (!AegisVpnService.isVpnRunning()) return false;
        try {
            JSONArray arr = new JSONArray(sCandidatesJson != null ? sCandidatesJson : "[]");
            if (arr.length() == 0) return false;

            String curTag = sActiveOutboundTag;
            String curName = AegisVpnService.getActiveNodeName();
            boolean isCellular = "cellular".equals(AegisVpnService.detectActiveNetworkType(ctx));

            List<JSONObject> wave1 = pickDiversifiedCandidates(arr, curTag, 6, isCellular, null);
            JSONObject winner = runCandidateRaceBatch(wave1, 2800, 5200);

            if (winner == null) {
                Set<String> triedTags = new HashSet<>();
                for (JSONObject w : wave1) triedTags.add(w.optString("tag", ""));
                List<JSONObject> wave2 = pickDiversifiedCandidates(arr, curTag, 8, true, triedTags);
                if (!wave2.isEmpty()) {
                    winner = runCandidateRaceBatch(wave2, 3000, 5400);
                }
            }

            if (winner == null) {
                // Если вообще ни один сервер не ответил — перепривязываем сокеты sing-box к текущей мобильной сети и проверяем заново
                boolean rebound = AegisVpnService.rebindAndRestartSingboxHot("Восстановление сокетов на мобильной сети");
                if (rebound) {
                    List<JSONObject> retryWave = pickDiversifiedCandidates(arr, null, 8, true, null);
                    winner = runCandidateRaceBatch(retryWave, 3000, 5400);
                }
            }

            if (winner != null) {
                String bestTag = winner.optString("tag", "");
                String bestName = winner.optString("name", "Резервный VPN");
                int bestDelay = winner.optInt("delay", 1);
                if (!bestTag.isEmpty()) {
                    boolean switched = AegisVpnService.switchActiveOutboundHot(bestTag, bestName);
                    if (switched) {
                        sActiveOutboundTag = bestTag;
                        rememberSuccessfulNetworkTag(ctx, bestTag);
                        sNativeSwitchCount += 1;
                        sLastSwitchFrom = curName != null ? curName : "Предыдущий VPN";
                        sLastSwitchTo = bestName;
                        sLastSwitchReason = reasonPrefix + " ➔ Умная гонка выбрала «" + bestName + "» (" + bestDelay + " мс)";
                        sLastSwitchTimestamp = System.currentTimeMillis();
                        if (ctx != null) {
                            AegisTileService.requestTileSync(ctx);
                            AegisWidgetProvider.refreshAllWidgets(ctx);
                        }
                        return true;
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private static JSONObject runCandidateRaceBatch(
            List<JSONObject> batch,
            final int perNodeTimeoutMs,
            long batchDeadlineMs
    ) {
        if (batch == null || batch.isEmpty()) return null;
        try {
            List<Callable<JSONObject>> tasks = new ArrayList<>();
            for (final JSONObject item : batch) {
                tasks.add(() -> {
                    String tag = item.optString("tag", "");
                    int delay = probeOutboundMultiTarget(tag, perNodeTimeoutMs);
                    JSONObject res = new JSONObject();
                    res.put("tag", tag);
                    res.put("name", item.optString("name", "Резервный VPN"));
                    res.put("delay", delay);
                    return res;
                });
            }

            List<Future<JSONObject>> futures = racePool.invokeAll(tasks, batchDeadlineMs, TimeUnit.MILLISECONDS);
            JSONObject best = null;
            int bestDelay = Integer.MAX_VALUE;
            for (Future<JSONObject> f : futures) {
                if (f.isDone() && !f.isCancelled()) {
                    try {
                        JSONObject r = f.get();
                        int d = r.optInt("delay", -1);
                        if (d > 0 && d < bestDelay) {
                            bestDelay = d;
                            best = r;
                        }
                    } catch (Exception ignored) {
                    }
                }
            }
            return best;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static boolean isMobileFriendlyCandidate(JSONObject obj) {
        if (obj == null) return false;
        if (obj.optBoolean("mobileFriendly", false)) return true;
        String name = obj.optString("name", "").toLowerCase(Locale.ROOT);
        return name.contains("lte")
                || name.contains("4g")
                || name.contains("5g")
                || name.contains("мобил")
                || name.contains("через рф")
                || name.contains("обход")
                || name.contains("white")
                || name.contains("вайт");
    }

    private static List<JSONObject> pickDiversifiedCandidates(
            JSONArray arr,
            String excludeTag,
            int maxCount,
            boolean preferMobileFriendly,
            Set<String> skipTags
    ) {
        List<JSONObject> all = new ArrayList<>();
        for (int i = 0; i < arr.length(); i++) {
            JSONObject obj = arr.optJSONObject(i);
            if (obj == null) continue;
            String tag = obj.optString("tag", "");
            if (tag.isEmpty()) continue;
            if (excludeTag != null && tag.equals(excludeTag)) continue;
            if (skipTags != null && skipTags.contains(tag)) continue;
            all.add(obj);
        }
        if (all.size() <= maxCount) return all;

        List<JSONObject> picked = new ArrayList<>();
        // Если телефон на мобильном интернете (LTE/4G) — в первую очередь берём специальные LTE / обходные серверы!
        if (preferMobileFriendly) {
            for (JSONObject obj : all) {
                if (picked.size() >= maxCount) break;
                if (isMobileFriendlyCandidate(obj) && !picked.contains(obj)) {
                    picked.add(obj);
                }
            }
        }

        Set<String> usedGroups = new HashSet<>();
        // Берём по одному лучшему серверу из каждого независимого VPN-провайдера/моста
        for (JSONObject obj : all) {
            if (picked.size() >= maxCount) break;
            String grp = obj.optString("group", "default");
            if (!usedGroups.contains(grp) && !picked.contains(obj)) {
                usedGroups.add(grp);
                picked.add(obj);
            }
        }
        // Добираем оставшиеся слоты по рейтингу
        for (JSONObject obj : all) {
            if (picked.size() >= maxCount) break;
            if (!picked.contains(obj)) {
                picked.add(obj);
            }
        }
        return picked;
    }

    private static JSONObject findCandidateByTag(JSONArray arr, String tag) {
        if (arr == null || tag == null || tag.isEmpty()) return null;
        for (int i = 0; i < arr.length(); i++) {
            JSONObject obj = arr.optJSONObject(i);
            if (obj != null && tag.equals(obj.optString("tag", ""))) {
                return obj;
            }
        }
        return null;
    }

    /**
     * Мгновенный 1.5-секундный хэндовер при смене физической сети (Wi-Fi <-> LTE или Wi-Fi 1 -> Wi-Fi 2):
     * 1) Параллельно за 1.5 сек проверяет: запомненный лучший сервер для новой сети (bestCellularTag / bestWifiTag),
     *    текущий сервер и топ-3 кандидата для этого типа сети.
     * 2) Если для новой сети есть проверенный чемпион (например, LTE #1 на мобильной сети или скоростной HY2 на домашнем Wi-Fi)
     *    и он быстрее/живее текущего — мгновенно переключает туннель за <= 1.5 сек!
     * 3) Если никто из быстрой четвёрки не ответил — запускает полную многоволновую гонку raceAndSwitchBestCandidate.
     */
    public static void onPhysicalNetworkHandover(final Context ctx, final String netType, final String reason) {
        if (!AegisVpnService.isVpnRunning()) return;
        try {
            JSONArray arr = new JSONArray(sCandidatesJson != null ? sCandidatesJson : "[]");
            if (arr.length() == 0) return;

            boolean isCell = "cellular".equals(netType);
            boolean autoProfileSwitch = true;
            try {
                JSONObject wCfg = new JSONObject(sWatchdogJson != null ? sWatchdogJson : "{}");
                autoProfileSwitch = wCfg.optBoolean("networkProfileAutoSwitch", true);
            } catch (Exception ignored) {
            }

            final String curTag = sActiveOutboundTag;
            final String curName = AegisVpnService.getActiveNodeName();
            final String rememberedTag = isCell ? sBestCellularOutboundTag : sBestWifiOutboundTag;

            List<JSONObject> fastGroup = new ArrayList<>();
            Set<String> addedTags = new HashSet<>();

            if (rememberedTag != null && !rememberedTag.isEmpty()) {
                JSONObject remObj = findCandidateByTag(arr, rememberedTag);
                if (remObj != null) {
                    fastGroup.add(remObj);
                    addedTags.add(rememberedTag);
                }
            }
            if (curTag != null && !curTag.isEmpty() && !addedTags.contains(curTag)) {
                JSONObject curObj = findCandidateByTag(arr, curTag);
                if (curObj != null) {
                    fastGroup.add(curObj);
                    addedTags.add(curTag);
                }
            }

            List<JSONObject> topForNet = pickDiversifiedCandidates(arr, null, 4, isCell, addedTags);
            for (JSONObject item : topForNet) {
                if (fastGroup.size() >= 5) break;
                String t = item.optString("tag", "");
                if (!t.isEmpty() && !addedTags.contains(t)) {
                    fastGroup.add(item);
                    addedTags.add(t);
                }
            }

            List<Callable<JSONObject>> tasks = new ArrayList<>();
            for (final JSONObject cand : fastGroup) {
                tasks.add(() -> {
                    String t = cand.optString("tag", "");
                    int d = probeOutboundFast1500(t, 1500);
                    JSONObject r = new JSONObject();
                    r.put("tag", t);
                    r.put("name", cand.optString("name", "VPN Сервер"));
                    r.put("delay", d);
                    r.put("mobileFriendly", isMobileFriendlyCandidate(cand));
                    return r;
                });
            }

            List<Future<JSONObject>> futures = racePool.invokeAll(tasks, 1650L, TimeUnit.MILLISECONDS);
            JSONObject curRes = null;
            JSONObject remRes = null;
            JSONObject fastestRes = null;
            int fastestDelay = Integer.MAX_VALUE;

            for (Future<JSONObject> f : futures) {
                if (f.isDone() && !f.isCancelled()) {
                    try {
                        JSONObject r = f.get();
                        int d = r.optInt("delay", -1);
                        String t = r.optString("tag", "");
                        if (t.equals(curTag)) curRes = r;
                        if (t.equals(rememberedTag)) remRes = r;
                        if (d > 0 && d < fastestDelay) {
                            fastestDelay = d;
                            fastestRes = r;
                        }
                    } catch (Exception ignored) {
                    }
                }
            }

            int curDelay = curRes != null ? curRes.optInt("delay", -1) : -1;
            boolean curMobileFriendly = curRes != null && curRes.optBoolean("mobileFriendly", false);
            int remDelay = remRes != null ? remRes.optInt("delay", -1) : -1;

            JSONObject chosen = null;
            String switchNote = reason;

            // 1. Если есть запомненный чемпион для этой сети и он живо ответил за <= 1.5 сек:
            if (autoProfileSwitch
                    && remRes != null
                    && remDelay > 0
                    && !rememberedTag.equals(curTag)
                    && (curDelay <= 0 || (isCell && !curMobileFriendly) || remDelay + 25 < curDelay)) {
                chosen = remRes;
                switchNote = isCell
                        ? "Авто-профиль LTE: выбран проверенный сервер мобильной сети"
                        : "Авто-профиль Wi-Fi: выбран самый быстрый домашний сервер";
            } else if (curDelay <= 0 && fastestRes != null) {
                // 2. Текущий сервер не ответил за 1.5 сек на новой сети — мгновенно переходим на победителя быстрой гонки
                chosen = fastestRes;
            } else if (isCell && !curMobileFriendly && fastestRes != null && fastestRes.optBoolean("mobileFriendly", false)) {
                // 3. На LTE переходим на мобильно-адаптированный узел (LTE / через РФ / Reality)
                chosen = fastestRes;
                switchNote = "Переход на LTE-адаптированный сервер";
            }

            if (chosen != null) {
                String targetTag = chosen.optString("tag", "");
                String targetName = chosen.optString("name", "VPN Сервер");
                int targetDelay = chosen.optInt("delay", 1);
                if (!targetTag.isEmpty() && !targetTag.equals(curTag)) {
                    if (AegisVpnService.switchActiveOutboundHot(targetTag, targetName)) {
                        sActiveOutboundTag = targetTag;
                        rememberSuccessfulNetworkTag(ctx, targetTag);
                        sNativeSwitchCount += 1;
                        sLastSwitchFrom = curName != null ? curName : "Предыдущий VPN";
                        sLastSwitchTo = targetName;
                        sLastSwitchReason = switchNote + " ➔ «" + targetName + "» (" + targetDelay + " мс)";
                        sLastSwitchTimestamp = System.currentTimeMillis();
                        ensureAiGatewayAliveOnHandover(arr);
                        return;
                    }
                }
            }

            if (curDelay > 0) {
                rememberSuccessfulNetworkTag(ctx, curTag);
                ensureAiGatewayAliveOnHandover(arr);
                return;
            }

            // 4. Если за 1.5 сек никто из быстрой группы не ответил — запускаем полную многоволновую гонку
            raceAndSwitchBestCandidate(ctx, reason);
            ensureAiGatewayAliveOnHandover(arr);
        } catch (Exception ignored) {
        }
    }

    private static boolean isRussianOrSuspiciousAiName(String name) {
        if (name == null || name.isEmpty()) return false;
        String lower = name.toLowerCase(Locale.ROOT);
        return lower.contains("🇷🇺")
                || lower.contains("🇧🇾")
                || lower.contains("росси")
                || lower.contains("москв")
                || lower.contains("спб")
                || lower.contains("питер")
                || lower.contains("через рф")
                || lower.contains("via ru")
                || lower.contains("lte")
                || lower.contains("4g")
                || lower.contains("5g")
                || lower.contains("обход")
                || lower.contains("вайт")
                || lower.contains("white")
                || lower.contains("youtube")
                || lower.contains("ютуб")
                || lower.contains("без реклам")
                || lower.matches(".*(^|[^a-zа-яё0-9])(рф|ru|rus|msk|spb)([^a-zа-яё0-9]|$).*");
    }

    private static List<JSONObject> buildSortedCleanAiPool(JSONArray arr) {
        List<JSONObject> verifiedClean = new ArrayList<>();
        List<JSONObject> unverifiedClean = new ArrayList<>();
        for (int i = 0; i < arr.length(); i++) {
            JSONObject item = arr.optJSONObject(i);
            if (item == null) continue;
            if (item.optBoolean("aiBlocked", false)) continue;
            String name = item.optString("name", "");
            boolean aiOk = item.optBoolean("aiOk", false);
            if (!aiOk && isRussianOrSuspiciousAiName(name)) continue;
            if (aiOk) {
                verifiedClean.add(item);
            } else {
                unverifiedClean.add(item);
            }
        }
        java.util.Comparator<JSONObject> byRankDesc = (a, b) ->
                Integer.compare(b.optInt("aiRank", 0), a.optInt("aiRank", 0));
        verifiedClean.sort(byRankDesc);
        unverifiedClean.sort(byRankDesc);
        List<JSONObject> combined = new ArrayList<>(verifiedClean.size() + unverifiedClean.size());
        combined.addAll(verifiedClean);
        combined.addAll(unverifiedClean);
        return combined;
    }

    private static void ensureAiGatewayAliveOnHandover(JSONArray arr) {
        try {
            String aiTag = sActiveAiOutboundTag;
            if (aiTag == null || aiTag.isEmpty()) return;
            JSONObject curAiObj = findCandidateByTag(arr, aiTag);
            boolean curBad = curAiObj != null && (
                    curAiObj.optBoolean("aiBlocked", false)
                            || (!curAiObj.optBoolean("aiOk", false) && isRussianOrSuspiciousAiName(curAiObj.optString("name", "")))
            );
            int d = curBad ? -1 : probeOutboundFast1500(aiTag, 1400);
            if (d <= 0) {
                switchBackupAiCandidate();
            }
        } catch (Exception ignored) {
        }
    }

    /**
     * Ручное переключение VPN-сервера из шторки уведомлений Android (🔄 Сменить VPN):
     * Сначала пытается выбрать самый быстрый живой сервер гонкой, а если во время перестроения сети
     * пробники не успели ответить — гарантированно переключает по кругу (Round-Robin) на следующий узел!
     */
    public static synchronized boolean switchNextOrRaceManual(Context ctx) {
        if (!AegisVpnService.isVpnRunning()) return false;
        boolean raced = raceAndSwitchBestCandidate(ctx, "Быстрая смена VPN из шторки");
        if (raced) return true;
        try {
            JSONArray arr = new JSONArray(sCandidatesJson != null ? sCandidatesJson : "[]");
            if (arr.length() == 0) return false;
            String curTag = sActiveOutboundTag;
            String curName = AegisVpnService.getActiveNodeName();
            int nextIdx = 0;
            for (int i = 0; i < arr.length(); i++) {
                JSONObject item = arr.optJSONObject(i);
                if (item != null && curTag.equals(item.optString("tag", ""))) {
                    nextIdx = (i + 1) % arr.length();
                    break;
                }
            }
            JSONObject nextObj = arr.optJSONObject(nextIdx);
            if (nextObj != null) {
                String nextTag = nextObj.optString("tag", "");
                String nextName = nextObj.optString("name", "Резервный VPN");
                if (!nextTag.isEmpty() && AegisVpnService.switchActiveOutboundHot(nextTag, nextName)) {
                    sActiveOutboundTag = nextTag;
                    sNativeSwitchCount += 1;
                    sLastSwitchFrom = curName != null ? curName : "Предыдущий VPN";
                    sLastSwitchTo = nextName;
                    sLastSwitchReason = "Смена сервера из шторки Android ➔ «" + nextName + "»";
                    sLastSwitchTimestamp = System.currentTimeMillis();
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    /**
     * Ручное переключение сервера ИИ-шлюза прямо из шторки уведомлений Android (🤖 Сменить ИИ).
     * Строго исключает российские, [через РФ], LTE-обходные и YouTube-RU серверы.
     */
    public static synchronized boolean switchNextAiManual(Context ctx) {
        if (!AegisVpnService.isVpnRunning()) return false;
        try {
            JSONArray arr = new JSONArray(sCandidatesJson != null ? sCandidatesJson : "[]");
            if (arr.length() == 0) return false;
            String curAi = sActiveAiOutboundTag;
            List<JSONObject> pool = buildSortedCleanAiPool(arr);
            if (pool.isEmpty()) return false;
            int nextIdx = 0;
            for (int i = 0; i < pool.size(); i++) {
                if (curAi.equals(pool.get(i).optString("tag", ""))) {
                    nextIdx = (i + 1) % pool.size();
                    break;
                }
            }
            for (int offset = 0; offset < pool.size(); offset++) {
                JSONObject cand = pool.get((nextIdx + offset) % pool.size());
                String tag = cand.optString("tag", "");
                String name = cand.optString("name", "AI Сервер");
                if (tag.isEmpty() || (tag.equals(curAi) && pool.size() > 1)) continue;
                int d = probeOutboundFast1500(tag, 1500);
                if (d > 0) {
                    if (!cand.optBoolean("aiOk", false)) {
                        JSONObject aiProbe = probeNodeAiCompatibility(tag, 4200);
                        String gCountry = aiProbe.optString("googleCountry", "");
                        String eCountry = aiProbe.optString("exitCountry", "");
                        if ("RU".equalsIgnoreCase(gCountry)
                                || "BY".equalsIgnoreCase(gCountry)
                                || "RU".equalsIgnoreCase(eCountry)
                                || "BY".equalsIgnoreCase(eCountry)
                                || "false".equalsIgnoreCase(aiProbe.optString("geminiHtmlAllowed", ""))) {
                            continue;
                        }
                    }
                    if (AegisVpnService.switchAiOutboundHot(tag, name)) {
                        return true;
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    public static synchronized void startWatchdogLoop(
            final Context ctx,
            String initialTag,
            String candidatesJson,
            String watchdogJson
    ) {
        stopWatchdogLoop();
        sActiveOutboundTag = initialTag != null ? initialTag : "";
        sCandidatesJson = candidatesJson != null ? candidatesJson : "[]";
        sWatchdogJson = watchdogJson != null ? watchdogJson : "{}";
        syncRememberedTagsFromWatchdogJson(sWatchdogJson);
        sWatchdogRunning = true;

        Thread worker = new Thread(() -> runLoopInternal(ctx), "AegisNative24x7Watchdog");
        worker.setDaemon(true);
        sWatchdogThread = worker;
        worker.start();
    }

    public static synchronized void updateCandidatesAndSettings(String candidatesJson, String watchdogJson) {
        if (candidatesJson != null && !candidatesJson.isEmpty()) {
            sCandidatesJson = candidatesJson;
        }
        if (watchdogJson != null && !watchdogJson.isEmpty()) {
            sWatchdogJson = watchdogJson;
            syncRememberedTagsFromWatchdogJson(watchdogJson);
        }
    }

    public static synchronized void stopWatchdogLoop() {
        sWatchdogRunning = false;
        if (sWatchdogThread != null) {
            try {
                sWatchdogThread.interrupt();
            } catch (Exception ignored) {
            }
            sWatchdogThread = null;
        }
    }

    private static void runLoopInternal(Context ctx) {
        int consecutiveFailures = 0;
        int aiConsecutiveFailures = 0;
        int tickCounter = 0;
        long[] prevStats = AegisVpnService.getTrafficStats();
        long prevTs = System.currentTimeMillis();

        while (sWatchdogRunning && AegisVpnService.isVpnRunning()) {
            int intervalSec = 8;
            int maxLatencyMs = 1500;
            int failureThreshold = 2;
            boolean speedEnabled = false;
            int minKbps = 350;
            boolean zombieEnabled = true;

            try {
                JSONObject cfg = new JSONObject(sWatchdogJson);
                intervalSec = Math.max(5, Math.min(cfg.optInt("intervalSec", 8), 60));
                maxLatencyMs = Math.max(400, cfg.optInt("maxLatencyMs", 1500));
                failureThreshold = Math.max(1, Math.min(cfg.optInt("failureThreshold", 2), 6));
                speedEnabled = cfg.optBoolean("speedEnabled", false);
                minKbps = Math.max(100, cfg.optInt("minKbps", 350));
                zombieEnabled = cfg.optBoolean("zombieEnabled", true);
            } catch (Exception ignored) {
            }

            try {
                Thread.sleep(intervalSec * 1000L);
            } catch (InterruptedException ie) {
                break;
            }

            if (!sWatchdogRunning || !AegisVpnService.isVpnRunning()) break;
            if (AegisVpnService.isCoreRestarting()) continue;
            String tag = sActiveOutboundTag;
            if (tag == null || tag.isEmpty()) continue;

            long now = System.currentTimeMillis();
            long[] currStats = AegisVpnService.getTrafficStats();
            long deltaTxPackets = currStats[0] - prevStats[0];
            long deltaRxBytes = currStats[3] - prevStats[3];
            long dtSec = Math.max(1L, (now - prevTs) / 1000L);
            prevStats = currStats;
            prevTs = now;

            // 1. Проверка на «зомби-зависание» (DPI заморозил поток: пакеты уходят, но 0 байт возвращается)
            boolean zombieSuspected = zombieEnabled && deltaTxPackets >= 14L && deltaRxBytes <= 64L;

            // 2. Двойная сквозная проверка задержки активного узла
            int delay = probeOutboundMultiTarget(tag, 3500);
            String failReason = null;

            if (delay <= 0) {
                failReason = zombieSuspected
                        ? "Обнаружена DPI-заморозка потока (зомби-туннель)"
                        : "Потеря сквозной связи в фоновом режиме";
            } else if (delay > maxLatencyMs) {
                failReason = "Высокая задержка туннеля (" + delay + " мс)";
            } else if (speedEnabled && deltaTxPackets >= 12L && deltaRxBytes > 1024L) {
                long observedKbps = (deltaRxBytes * 8L) / (dtSec * 1000L);
                if (observedKbps > 0 && observedKbps < (minKbps / 2L)) {
                    int burstKbps = measureTunnelBandwidthKbps(98304, 3400);
                    if (burstKbps > 0 && burstKbps < minKbps) {
                        failReason = "Просадка скорости туннеля (" + burstKbps + " Кбит/с < " + minKbps + " Кбит/с)";
                    }
                }
            }

            if (failReason != null) {
                consecutiveFailures += 1;
                if (consecutiveFailures >= failureThreshold) {
                    boolean switched = raceAndSwitchBestCandidate(ctx, failReason);
                    if (switched) {
                        consecutiveFailures = 0;
                        prevStats = AegisVpnService.getTrafficStats();
                        prevTs = System.currentTimeMillis();
                    }
                }
            } else {
                consecutiveFailures = 0;
                rememberSuccessfulNetworkTag(ctx, tag);
            }

            // 3. Бережная фоновая страховка выделенного ИИ-шлюза proxy-ai (Gemini / ChatGPT / Grok):
            // Не переключаем ИИ-сервер без необходимости, но если он упал — мгновенно ставим резервный AI-совместимый узел!
            tickCounter += 1;
            String aiTag = sActiveAiOutboundTag;
            if (tickCounter % 2 == 0 && aiTag != null && !aiTag.isEmpty() && !aiTag.equals(sActiveOutboundTag)) {
                int aiDelay = probeOutboundMultiTarget(aiTag, 3200);
                if (aiDelay <= 0) {
                    aiConsecutiveFailures += 1;
                    if (aiConsecutiveFailures >= 2) {
                        switchBackupAiCandidate();
                        aiConsecutiveFailures = 0;
                    }
                } else {
                    aiConsecutiveFailures = 0;
                }
            }
        }
    }

    private static void switchBackupAiCandidate() {
        try {
            JSONArray arr = new JSONArray(sCandidatesJson != null ? sCandidatesJson : "[]");
            String curAi = sActiveAiOutboundTag;
            List<JSONObject> pool = buildSortedCleanAiPool(arr);
            for (JSONObject item : pool) {
                String tag = item.optString("tag", "");
                if (tag.isEmpty() || tag.equals(curAi)) continue;
                int d = probeOutboundMultiTarget(tag, 2800);
                if (d > 0) {
                    String name = item.optString("name", "AI Сервер");
                    if (AegisVpnService.switchAiOutboundHot(tag, name)) {
                        return;
                    }
                }
            }
        } catch (Exception ignored) {
        }
    }
}
