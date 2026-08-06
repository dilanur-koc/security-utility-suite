package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.HeaderAuditRequest;
import com.example.securityutilitysuite.dto.HeaderAuditResponse;
import com.example.securityutilitysuite.security.NetworkGuard;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Bir adresin HTTP guvenlik basliklarini denetler ve agirlikli bir puan uretir.
 *
 * Tasarim notlari:
 * - Tek bir GET istegi atilir; icerik indirilmez (yanit govdesi atilir), yalnizca
 *   basliklar okunur. Boylece buyuk sayfalarda bile maliyet dusuk kalir.
 * - Puanlama agirliklidir: HSTS ve CSP gibi gercekten saldiri yuzeyini daraltan
 *   basliklar, X-XSS-Protection gibi artik onerilmeyen basliklardan daha
 *   degerlidir. Basligin sadece VARLIGI degil, DEGERI de incelenir — ornegin
 *   script-src icinde "unsafe-inline" iceren bir CSP, korumanin buyuk
 *   kismini kaybettirir (style-src icinde ise risk cok daha dusuktur).
 * - Modul durum tutmaz, veritabanina yazmaz.
 */
@Service
public class HttpHeaderAuditService {

    private final NetworkGuard networkGuard;

    public HttpHeaderAuditService(NetworkGuard networkGuard) {
        this.networkGuard = networkGuard;
    }

    private static final Logger log = LoggerFactory.getLogger(HttpHeaderAuditService.class);

    private static final Duration TIMEOUT = Duration.ofSeconds(10);
    private static final String USER_AGENT = "security-utility-suite/1.0 (header audit)";
    private static final int MAX_REDIRECTS = 5;

    /** Sunucu hakkinda bilgi sizdiran, kaldirilmasi onerilen basliklar. */
    private static final List<String> LEAKY_HEADERS =
            List.of("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator");

    public HeaderAuditResponse audit(HeaderAuditRequest request) {
        String url = request.getUrl().trim();
        long start = System.currentTimeMillis();

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(TIMEOUT)
                // Yonlendirmeleri HttpClient'a birakmiyoruz: her hop'u kendimiz
                // dogrulayip takip ediyoruz, boylece guvenli gorunen bir adres
                // ic aga/metadata servisine yonlendirerek SSRF korumasini
                // atlatamiyor.
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        HttpResponse<Void> response;
        String currentUrl = url;
        try {
            int hops = 0;
            while (true) {
                networkGuard.verifyPublicTarget(URI.create(currentUrl).getHost());

                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create(currentUrl))
                        .timeout(TIMEOUT)
                        .header("User-Agent", USER_AGENT)
                        .GET()
                        .build();

                // Govde indirilmez; sadece basliklar lazim.
                HttpResponse<Void> res = client.send(req, HttpResponse.BodyHandlers.discarding());

                int status = res.statusCode();
                boolean isRedirect = status == 301 || status == 302 || status == 303
                        || status == 307 || status == 308;

                if (!isRedirect || !request.isFollowRedirects()) {
                    response = res;
                    break;
                }

                if (++hops > MAX_REDIRECTS) {
                    throw new IllegalArgumentException("Çok fazla yönlendirme (>" + MAX_REDIRECTS + ")");
                }

                String location = res.headers().firstValue("location")
                        .orElseThrow(() -> new IllegalArgumentException(
                                status + " yönlendirmesi ama Location başlığı yok"));
                currentUrl = res.uri().resolve(location).toString();
            }
        } catch (IllegalArgumentException ex) {
            // SSRF guard veya redirect hatasi: kullaniciya net sebep donuyoruz.
            log.warn("Baslik denetimi engellendi url={}: {}", currentUrl, ex.getMessage());
            return HeaderAuditResponse.unreachable(url, ex.getMessage());
        } catch (Exception ex) {
            log.warn("Baslik denetimi basarisiz url={}: {}", currentUrl, ex.getMessage());
            return HeaderAuditResponse.unreachable(url, kisaHata(ex));
        }

        long elapsed = System.currentTimeMillis() - start;

        Map<String, String> headers = new LinkedHashMap<>();
        response.headers().map().forEach((k, v) ->
                headers.put(k.toLowerCase(), String.join(", ", v)));

        boolean https = response.uri().getScheme().equalsIgnoreCase("https");
        List<HeaderAuditResponse.HeaderCheck> checks = denetle(headers, https);
        List<HeaderAuditResponse.Finding> findings = bulgular(headers, checks, https, response.statusCode());

        int score = puanla(checks);
        return new HeaderAuditResponse(
                url, response.uri().toString(), true, null,
                response.statusCode(), String.valueOf(response.version()), elapsed,
                score, harfNotu(score), checks, headers, findings
        );
    }

    // ------------------------------------------------------------------
    // Baslik denetimleri
    // ------------------------------------------------------------------

    private List<HeaderAuditResponse.HeaderCheck> denetle(Map<String, String> h, boolean https) {
        List<HeaderAuditResponse.HeaderCheck> checks = new ArrayList<>();

        // --- HSTS (yalnizca HTTPS'te anlamli) ---
        String hsts = h.get("strict-transport-security");
        if (!https) {
            checks.add(check("Strict-Transport-Security", false, null, "MISSING", 20,
                    "Tarayıcıya siteye yalnızca HTTPS ile bağlanmasını söyler.",
                    "Site HTTP üzerinden sunuluyor; HSTS yalnızca HTTPS'te geçerlidir."));
        } else if (hsts == null) {
            checks.add(check("Strict-Transport-Security", false, null, "MISSING", 20,
                    "Tarayıcıya siteye yalnızca HTTPS ile bağlanmasını söyler.",
                    "SSL sıyırma (SSL stripping) saldırılarına açık."));
        } else {
            long maxAge = maxAgeOku(hsts);
            String note = null;
            String status = "OK";
            if (maxAge < 15552000) { // 180 gün
                status = "WARN";
                note = "max-age " + maxAge + " sn — önerilen en az 15552000 (180 gün).";
            } else if (!hsts.toLowerCase().contains("includesubdomains")) {
                status = "WARN";
                note = "includeSubDomains yok; alt alan adları korumasız.";
            }
            checks.add(check("Strict-Transport-Security", true, hsts, status, 20,
                    "Tarayıcıya siteye yalnızca HTTPS ile bağlanmasını söyler.", note));
        }

        // --- CSP ---
        String csp = h.get("content-security-policy");
        if (csp == null) {
            String ro = h.get("content-security-policy-report-only");
            checks.add(check("Content-Security-Policy", false, ro, "MISSING", 25,
                    "Hangi kaynaklardan script/stil yüklenebileceğini kısıtlar; XSS'e karşı en güçlü savunma.",
                    ro != null ? "Yalnızca report-only modda tanımlı; hiçbir şeyi engellemiyor." : null));
        } else {
            String lower = csp.toLowerCase();
            String note = null;
            String status = "OK";

            // 'unsafe-inline' HANGI DIREKTIFTE oldugu belirleyicidir:
            // script-src/default-src icinde ise XSS korumasi buyuk olcude
            // etkisizlesir. style-src icinde ise risk cok daha dusuktur ve
            // yaygin bir pratiktir (orn. GitHub boyle yapar). Ikisini ayni
            // saymak, iyi yapilandirilmis siteleri haksiz yere cezalandirir.
            boolean scriptUnsafeInline = direktifIceriyorMu(lower, "script-src", "'unsafe-inline'")
                    || (!direktifVarMi(lower, "script-src")
                        && direktifIceriyorMu(lower, "default-src", "'unsafe-inline'"));
            boolean styleUnsafeInline = direktifIceriyorMu(lower, "style-src", "'unsafe-inline'");

            if (scriptUnsafeInline) {
                status = "WARN";
                note = "script-src içinde 'unsafe-inline' var; XSS koruması büyük ölçüde etkisiz.";
            } else if (lower.contains("unsafe-eval")) {
                status = "WARN";
                note = "'unsafe-eval' kullanılıyor; dinamik kod çalıştırmaya izin veriyor.";
            } else if (lower.contains("default-src *") || lower.contains("script-src *")) {
                status = "WARN";
                note = "Joker (*) kaynak tanımı var; kısıtlama etkisiz kalıyor.";
            } else if (styleUnsafeInline) {
                // Puani dusurmez; yalnizca bilgi notu.
                note = "style-src içinde 'unsafe-inline' var; script'e göre düşük riskli, yaygın bir kullanım.";
            }
            checks.add(check("Content-Security-Policy", true, csp, status, 25,
                    "Hangi kaynaklardan script/stil yüklenebileceğini kısıtlar; XSS'e karşı en güçlü savunma.", note));
        }

        // --- X-Frame-Options / frame-ancestors ---
        String xfo = h.get("x-frame-options");
        boolean frameAncestors = csp != null && csp.toLowerCase().contains("frame-ancestors");
        if (xfo == null && !frameAncestors) {
            checks.add(check("X-Frame-Options", false, null, "MISSING", 15,
                    "Sayfanın iframe içine gömülmesini engeller; clickjacking'e karşı korur.",
                    "CSP frame-ancestors da tanımlı değil."));
        } else if (xfo == null) {
            checks.add(check("X-Frame-Options", false, null, "OK", 15,
                    "Sayfanın iframe içine gömülmesini engeller; clickjacking'e karşı korur.",
                    "Başlık yok ama CSP frame-ancestors ile karşılanıyor (modern yöntem)."));
        } else {
            String v = xfo.trim().toUpperCase();
            boolean gecerli = v.equals("DENY") || v.equals("SAMEORIGIN");
            checks.add(check("X-Frame-Options", true, xfo, gecerli ? "OK" : "WARN", 15,
                    "Sayfanın iframe içine gömülmesini engeller; clickjacking'e karşı korur.",
                    gecerli ? null : "Beklenen değer DENY veya SAMEORIGIN."));
        }

        // --- X-Content-Type-Options ---
        String xcto = h.get("x-content-type-options");
        boolean nosniff = xcto != null && xcto.trim().equalsIgnoreCase("nosniff");
        checks.add(check("X-Content-Type-Options", xcto != null, xcto,
                nosniff ? "OK" : (xcto == null ? "MISSING" : "WARN"), 10,
                "Tarayıcının içerik türünü tahmin etmesini engeller (MIME sniffing).",
                xcto != null && !nosniff ? "Tek geçerli değer 'nosniff'." : null));

        // --- Referrer-Policy ---
        String ref = h.get("referrer-policy");
        checks.add(check("Referrer-Policy", ref != null, ref,
                ref == null ? "MISSING" : "OK", 10,
                "Başka sitelere hangi adres bilgisinin gönderileceğini belirler.",
                ref != null && ref.toLowerCase().contains("unsafe-url")
                        ? "'unsafe-url' tam adresi HTTP sitelerine de sızdırır." : null));

        // --- Permissions-Policy ---
        String pp = h.get("permissions-policy");
        if (pp == null) pp = h.get("feature-policy");
        checks.add(check("Permissions-Policy", pp != null, pp,
                pp == null ? "MISSING" : "OK", 10,
                "Kamera, mikrofon, konum gibi tarayıcı özelliklerine erişimi kısıtlar.", null));

        // --- Cross-Origin-Opener-Policy ---
        String coop = h.get("cross-origin-opener-policy");
        checks.add(check("Cross-Origin-Opener-Policy", coop != null, coop,
                coop == null ? "MISSING" : "OK", 5,
                "Sayfayı başka kaynaklardan açılan pencerelerden yalıtır.", null));

        // --- Cross-Origin-Resource-Policy ---
        String corp = h.get("cross-origin-resource-policy");
        checks.add(check("Cross-Origin-Resource-Policy", corp != null, corp,
                corp == null ? "MISSING" : "OK", 5,
                "Kaynakların başka sitelerce yüklenmesini kısıtlar.", null));

        return checks;
    }

    // ------------------------------------------------------------------
    // Bulgular
    // ------------------------------------------------------------------

    private List<HeaderAuditResponse.Finding> bulgular(
            Map<String, String> h, List<HeaderAuditResponse.HeaderCheck> checks,
            boolean https, int statusCode) {

        List<HeaderAuditResponse.Finding> f = new ArrayList<>();

        if (!https) {
            f.add(new HeaderAuditResponse.Finding("HIGH",
                    "Site HTTP üzerinden sunuluyor. Trafik şifresiz; araya girme saldırılarına açık."));
        }

        for (HeaderAuditResponse.HeaderCheck c : checks) {
            if ("MISSING".equals(c.status())) {
                String sev = c.weight() >= 20 ? "HIGH" : (c.weight() >= 10 ? "MEDIUM" : "LOW");
                f.add(new HeaderAuditResponse.Finding(sev, c.name() + " başlığı yok. " + c.description()));
            } else if ("WARN".equals(c.status()) && c.note() != null) {
                f.add(new HeaderAuditResponse.Finding("MEDIUM", c.name() + ": " + c.note()));
            }
        }

        // Bilgi sizdiran basliklar
        for (String leaky : LEAKY_HEADERS) {
            String v = h.get(leaky);
            if (v != null && !v.isBlank()) {
                f.add(new HeaderAuditResponse.Finding("LOW",
                        "'" + leaky + "' başlığı sunucu/teknoloji bilgisi sızdırıyor: " + v));
            }
        }

        // Cerez guvenligi
        String cookies = h.get("set-cookie");
        if (cookies != null) {
            String lower = cookies.toLowerCase();
            if (!lower.contains("httponly")) {
                f.add(new HeaderAuditResponse.Finding("HIGH",
                        "Çerezlerde HttpOnly yok; JavaScript ile okunabilirler."));
            }
            if (https && !lower.contains("secure")) {
                f.add(new HeaderAuditResponse.Finding("HIGH",
                        "Çerezlerde Secure yok; şifresiz bağlantıda da gönderilebilirler."));
            }
            if (!lower.contains("samesite")) {
                f.add(new HeaderAuditResponse.Finding("MEDIUM",
                        "Çerezlerde SameSite yok; CSRF riskini artırır."));
            }
        }

        if (statusCode >= 400) {
            f.add(new HeaderAuditResponse.Finding("LOW",
                    "Sunucu " + statusCode + " döndürdü; başlıklar hata sayfasına ait olabilir."));
        }

        return f;
    }

    // ------------------------------------------------------------------
    // Puanlama
    // ------------------------------------------------------------------

    private int puanla(List<HeaderAuditResponse.HeaderCheck> checks) {
        int toplam = 0;
        int kazanilan = 0;
        for (HeaderAuditResponse.HeaderCheck c : checks) {
            toplam += c.weight();
            if ("OK".equals(c.status())) {
                kazanilan += c.weight();
            } else if ("WARN".equals(c.status())) {
                // Yanlis yapilandirilmis bir baslik, hic olmamasindan iyidir ama tam puan almaz.
                kazanilan += c.weight() / 2;
            }
        }
        return toplam == 0 ? 0 : Math.round((kazanilan * 100f) / toplam);
    }

    private String harfNotu(int score) {
        if (score >= 85) return "A+";
        if (score >= 70) return "A";
        if (score >= 55) return "B";
        if (score >= 40) return "C";
        if (score >= 25) return "D";
        return "F";
    }

    // ------------------------------------------------------------------
    // SSRF korumasi
    // ------------------------------------------------------------------

    /**
     * Hedef URL'nin host'unu cozup, cozulen HERHANGI bir IP ozel/dahili bir
     * araliga dusuyorsa istegi reddeder. Bu kontrol hem ilk istekte hem de
     * her yonlendirme adiminda tekrar cagrilir; aksi halde saldirgan once
     * herkese acik bir adrese, sonra 302 ile ic aga yonlendirebilirdi.
     *
     * DNS rebinding'e karsi tam koruma saglamaz (cozum ile baglanti arasinda
     * kayit degisebilir), ama bu, dogrudan literal ic IP/host verilmesini ve
     * basit redirect tabanli SSRF'i engeller.
     */
    // ------------------------------------------------------------------
    // Yardimcilar
    // ------------------------------------------------------------------

    /** CSP icinde belirtilen direktif tanimli mi? */
    private boolean direktifVarMi(String cspLower, String direktif) {
        for (String parca : cspLower.split(";")) {
            if (parca.trim().startsWith(direktif + " ") || parca.trim().equals(direktif)) {
                return true;
            }
        }
        return false;
    }

    /** Belirtilen direktif, verilen anahtar kelimeyi iceriyor mu? */
    private boolean direktifIceriyorMu(String cspLower, String direktif, String anahtar) {
        for (String parca : cspLower.split(";")) {
            String t = parca.trim();
            if (t.startsWith(direktif + " ") && t.contains(anahtar)) {
                return true;
            }
        }
        return false;
    }

    private HeaderAuditResponse.HeaderCheck check(String name, boolean present, String value,
                                                  String status, int weight,
                                                  String description, String note) {
        return new HeaderAuditResponse.HeaderCheck(name, present, value, status, weight, description, note);
    }

    private long maxAgeOku(String hsts) {
        try {
            for (String part : hsts.split(";")) {
                String p = part.trim().toLowerCase();
                if (p.startsWith("max-age")) {
                    return Long.parseLong(p.split("=")[1].trim().replaceAll("\"", ""));
                }
            }
        } catch (Exception ignored) {
            // bicim bozuksa 0 kabul edilir
        }
        return 0;
    }

    private String kisaHata(Exception ex) {
        String msg = ex.getMessage();
        if (msg == null || msg.isBlank()) return ex.getClass().getSimpleName();
        return msg.length() > 200 ? msg.substring(0, 200) + "…" : msg;
    }
}
