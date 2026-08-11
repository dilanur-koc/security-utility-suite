package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.Finding;
import com.example.securityutilitysuite.dto.WebVulnParamResult;
import com.example.securityutilitysuite.dto.WebVulnScanRequest;
import com.example.securityutilitysuite.dto.WebVulnScanResponse;
import com.example.securityutilitysuite.security.NetworkGuard;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

@Service
public class WebVulnScannerService {

    private static final Logger log = LoggerFactory.getLogger(WebVulnScannerService.class);

    private static final int MIN_DELAY_MS = 200;
    private static final int MAX_DELAY_MS = 500;
    private static final int MAX_PARAMETERS = 10;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private static final List<String> XSS_PAYLOADS = List.of(
            "<script>alert('XSS')</script>",
            "\"><img src=x onerror=alert(1)>"
    );
    private static final String SQLI_TRUE = "' OR '1'='1";
    private static final String SQLI_FALSE = "1' AND '1'='2";
    private static final String SQLI_ERROR_TRIGGER = "'";

    private static final List<String> SQL_ERROR_SIGNATURES = List.of(
            "sql syntax", "mysql_fetch", "you have an error in your sql syntax",
            "warning: mysql", "unclosed quotation mark", "quoted string not properly terminated",
            "ora-01756", "ora-00933", "postgresql.util.psqlexception", "sqlite3::",
            "sqlstate", "pg_query", "microsoft ole db provider for odbc drivers",
            "odbc sql server driver", "npgsql.", "system.data.sqlclient"
    );

    private final NetworkGuard networkGuard;
    private final Random random = new Random();

    public WebVulnScannerService(NetworkGuard networkGuard) {
        this.networkGuard = networkGuard;
    }

    public WebVulnScanResponse scan(WebVulnScanRequest request) {
        if (!request.legalAcknowledgement()) {
            throw new IllegalArgumentException(
                    "Yasal sorumluluk onayı işaretlenmeden tarama başlatılamaz. "
                            + "Bu aracı yalnızca test etme yetkiniz olan sistemlerde kullanın.");
        }

        URI baseUri;
        try {
            // 💡 URL'i pars etmeden önce sanitize ediyoruz (Illegal character hatasını önler)
            String cleanUrl = sanitizeUrl(request.url());
            baseUri = new URI(cleanUrl);
        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException("Geçersiz URL: " + ex.getMessage());
        }

        String host = baseUri.getHost();
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("URL'den bir host bilgisi çıkarılamadı.");
        }

        // 1) SSRF filtresi — zorunlu, atlanamaz.
        networkGuard.verifyPublicTarget(host);

        Map<String, String> params = parseQuery(baseUri.getRawQuery());
        List<Finding> findings = new ArrayList<>();
        List<WebVulnParamResult> results = new ArrayList<>();

        if (params.isEmpty()) {
            findings.add(Finding.low(
                    "URL herhangi bir sorgu parametresi içermiyor — test edilecek bir girdi alanı yok."));
            return new WebVulnScanResponse(request.url(), 0, 0, results, findings);
        }

        List<String> testedParams = params.keySet().stream().limit(MAX_PARAMETERS).toList();
        if (testedParams.size() < params.size()) {
            findings.add(Finding.low("Parametre sayısı sınırı (" + MAX_PARAMETERS + ") aşıldığı için yalnızca ilk "
                    + MAX_PARAMETERS + " parametre test edildi."));
        }

        // 2) Yalnizca GET — bu HttpClient hicbir zaman baska bir metodla cagrilmaz.
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER) // redirect ile SSRF atlatmayi onler
                .connectTimeout(REQUEST_TIMEOUT)
                .build();

        int requestsSent = 0;

        HttpResponseData baseline = fetch(client, buildUrl(baseUri, params, null, null));
        requestsSent++;
        throttle();

        for (String param : testedParams) {
            boolean xssHit = false;
            for (String payload : XSS_PAYLOADS) {
                HttpResponseData resp = fetch(client, buildUrl(baseUri, params, param, payload));
                requestsSent++;
                throttle();
                if (resp != null && xssReflected(resp.body(), payload)) {
                    xssHit = true;
                    break;
                }
            }

            HttpResponseData errResp = fetch(client, buildUrl(baseUri, params, param, SQLI_ERROR_TRIGGER));
            requestsSent++;
            throttle();
            boolean sqlErrorHit = errResp != null && sqlErrorDetected(errResp.body());

            HttpResponseData trueResp = fetch(client, buildUrl(baseUri, params, param, SQLI_TRUE));
            requestsSent++;
            throttle();
            HttpResponseData falseResp = fetch(client, buildUrl(baseUri, params, param, SQLI_FALSE));
            requestsSent++;
            throttle();

            boolean booleanHit = baseline != null && trueResp != null && falseResp != null
                    && booleanSqliSuspected(baseline.body().length(), trueResp.body().length(), falseResp.body().length());

            results.add(new WebVulnParamResult(param, xssHit, sqlErrorHit, booleanHit));

            if (xssHit) {
                findings.add(Finding.critical("\"" + param + "\" parametresi Reflected XSS'e açık görünüyor — "
                        + "girilen script/etiket, yanıt gövdesinde kaçırılmadan (unescaped) geri dönüyor."));
            }
            if (sqlErrorHit) {
                findings.add(Finding.critical("\"" + param + "\" parametresi hata tabanlı SQL enjeksiyonuna açık "
                        + "görünüyor — yanıt bir veritabanı hata imzası içeriyor."));
            }
            if (booleanHit) {
                findings.add(Finding.high("\"" + param + "\" parametresinde boolean tabanlı SQL enjeksiyonu şüphesi — "
                        + "\"doğru\" ve \"yanlış\" koşullu girdiler belirgin şekilde farklı uzunlukta yanıt üretiyor."));
            }
        }

        boolean hasRealFinding = findings.stream().anyMatch(f -> !f.severity().equals("LOW"));
        if (!hasRealFinding) {
            findings.add(Finding.low("Test edilen parametrelerde belirgin bir XSS/SQLi belirtisi bulunamadı. "
                    + "Bu, hedefin güvenli olduğu anlamına gelmez — yalnızca bu basit yansıma testlerini geçtiği anlamına gelir."));
        }

        return new WebVulnScanResponse(request.url(), testedParams.size(), requestsSent, results, findings);
    }

    // ------------------------------------------------------------------
    // Ag cagrisi
    // ------------------------------------------------------------------

    private record HttpResponseData(int status, String body) {
    }

    private HttpResponseData fetch(HttpClient client, URI uri) {
        try {
            HttpRequest req = HttpRequest.newBuilder(uri)
                    .timeout(REQUEST_TIMEOUT)
                    .GET()
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            return new HttpResponseData(resp.statusCode(), resp.body() == null ? "" : resp.body());
        } catch (Exception ex) {
            log.debug("Web zafiyet taramasi istegi basarisiz (atlanip devam edilecek): {}", ex.getMessage());
            return null;
        }
    }

    private void throttle() {
        try {
            Thread.sleep(MIN_DELAY_MS + random.nextInt(MAX_DELAY_MS - MIN_DELAY_MS + 1));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // ------------------------------------------------------------------
    // URL insasi & Temizleme
    // ------------------------------------------------------------------

    private Map<String, String> parseQuery(String rawQuery) {
        Map<String, String> map = new LinkedHashMap<>();
        if (rawQuery == null || rawQuery.isBlank()) return map;
        for (String pair : rawQuery.split("&")) {
            int idx = pair.indexOf('=');
            if (idx < 0) continue;
            String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
            String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
            map.put(key, value);
        }
        return map;
    }

    private URI buildUrl(URI base, Map<String, String> originalParams, String paramToReplace, String payload) {
        StringBuilder query = new StringBuilder();
        for (Map.Entry<String, String> e : originalParams.entrySet()) {
            if (!query.isEmpty()) query.append('&');
            String value = e.getKey().equals(paramToReplace) ? payload : e.getValue();
            query.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
                    .append('=')
                    .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
        }
        try {
            return new URI(base.getScheme(), base.getAuthority(), base.getPath(), query.toString(), null);
        } catch (URISyntaxException ex) {
            throw new IllegalStateException("URL yeniden oluşturulamadı: " + ex.getMessage(), ex);
        }
    }

    private String sanitizeUrl(String url) {
        if (url == null || url.isBlank()) {
            return url;
        }
        return url.trim()
                .replace("<", "%3C")
                .replace(">", "%3E")
                .replace(" ", "%20")
                .replace("'", "%27")
                .replace("\"", "%22");
    }

    // ------------------------------------------------------------------
    // Tespit mantigi
    // ------------------------------------------------------------------

    static boolean xssReflected(String responseBody, String payload) {
        return responseBody != null && responseBody.contains(payload);
    }

    static boolean sqlErrorDetected(String responseBody) {
        if (responseBody == null) return false;
        String lower = responseBody.toLowerCase();
        return SQL_ERROR_SIGNATURES.stream().anyMatch(lower::contains);
    }

    static boolean booleanSqliSuspected(int baselineLen, int trueLen, int falseLen) {
        if (baselineLen == 0) return false;
        double trueDiffRatio = Math.abs(trueLen - baselineLen) / (double) baselineLen;
        double falseDiffRatio = Math.abs(falseLen - baselineLen) / (double) baselineLen;
        return trueDiffRatio < 0.1 && falseDiffRatio > 0.3 && Math.abs(trueLen - falseLen) > 20;
    }
}