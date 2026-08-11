package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.Finding;
import com.example.securityutilitysuite.dto.PhishingCheckRequest;
import com.example.securityutilitysuite.dto.PhishingCheckResponse;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Phishing URL Detector.
 *
 * ONEMLI KAPSAM NOTU: Bu modul TAMAMEN PASIFTIR — hedef URL'ye HICBIR AGLAYICI
 * ISTEK GONDERMEZ (SSRF riski yoktur). Yalnizca URL METNININ YAPISINI analiz
 * eder: typosquatting (Levenshtein mesafesi), supheli TLD, IP tabanli adres,
 * punycode, asiri alt alan adi derinligi, marka adi/kok alan adi uyusmazligi,
 * userinfo ("@") hilesi. Bir sonraki modul (Web Zafiyet Tarayici) bunun
 * aksine hedefe gercekten istek gonderecek ve NetworkGuard + hiz siniri
 * gerektirecek — bu modul o kategoriye girmiyor.
 *
 * Kayitli alan adi (registrable domain) tespiti basitlestirilmis: son iki
 * etiket alinir (orn. "mail.google.com" -> "google.com"). Bu, ".co.uk" gibi
 * cok parcali TLD'lerde yanlis sonuc verebilir (public suffix list
 * kullanilmiyor) — v1 icin kabul edilebilir bir sinirlama, README'de belirtildi.
 */
@Service
public class PhishingDetectorService {

    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
            "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click", "link",
            "zip", "review", "country", "kim", "men", "loan", "download",
            "racing", "win", "party", "science", "cricket", "accountant", "stream"
    );

    /** Marka -> tam kayitli alan adi. Typosquat karsilastirmasinda kullanilir. */
    private static final Map<String, String> KNOWN_BRANDS = brandMap();

    private static Map<String, String> brandMap() {
        Map<String, String> m = new LinkedHashMap<>();
        String[] domains = {
                "google.com", "youtube.com", "facebook.com", "instagram.com",
                "whatsapp.com", "twitter.com", "apple.com", "microsoft.com",
                "amazon.com", "netflix.com", "paypal.com", "ebay.com",
                "linkedin.com", "github.com", "dropbox.com", "spotify.com",
                "yahoo.com", "outlook.com", "bankofamerica.com", "chase.com",
                "wellsfargo.com", "americanexpress.com", "steampowered.com",
                "adobe.com", "icloud.com", "binance.com", "coinbase.com"
        };
        for (String d : domains) {
            String brand = d.substring(0, d.indexOf('.'));
            m.put(brand, d);
        }
        return m;
    }

    private static final Pattern IPV4 = Pattern.compile(
            "^(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)$");

    private static final int MAX_SUBDOMAIN_DEPTH = 3;

    public PhishingCheckResponse analyze(PhishingCheckRequest request) {
        String raw = request.url() == null ? "" : request.url().trim();

        URI uri;
        try {
            String withScheme = raw.matches("(?i)^[a-z][a-z0-9+.\\-]*://.*") ? raw : "http://" + raw;
            uri = new URI(withScheme);
        } catch (URISyntaxException ex) {
            return new PhishingCheckResponse(false, raw, null, null, false, false, false,
                    null, 0, List.of(), null, null,
                    List.of(Finding.low("URL ayrıştırılamadı — geçerli bir http/https adresi girin.")));
        }

        String scheme = uri.getScheme();
        String host = uri.getHost();
        String userInfo = uri.getUserInfo();

        if (host == null || host.isBlank()) {
            return new PhishingCheckResponse(false, raw, scheme, null, false, false, false,
                    null, 0, List.of(), null, null,
                    List.of(Finding.low("URL'den bir host bilgisi çıkarılamadı.")));
        }

        String hostLower = host.toLowerCase();
        boolean ipBased = IPV4.matcher(hostLower).matches() || hostLower.contains(":"); // kaba IPv6 tespiti
        boolean punycode = hostLower.contains("xn--");
        boolean hasUserInfoTrick = userInfo != null && !userInfo.isBlank();

        String[] labels = hostLower.split("\\.");
        String tld = labels.length > 0 ? labels[labels.length - 1] : "";
        String suspiciousTld = SUSPICIOUS_TLDS.contains(tld) ? tld : null;

        String registrableDomain = ipBased || labels.length < 2
                ? hostLower
                : labels[labels.length - 2] + "." + labels[labels.length - 1];

        int subdomainDepth = ipBased ? 0 : Math.max(0, labels.length - 2);

        List<String> brandKeywords = new ArrayList<>();
        String closestBrand = null;
        Integer closestDistance = null;

        if (!ipBased) {
            for (Map.Entry<String, String> brand : KNOWN_BRANDS.entrySet()) {
                String brandName = brand.getKey();
                String brandDomain = brand.getValue();

                if (registrableDomain.equals(brandDomain)) {
                    continue; // gercek marka sitesi, supheli degil
                }
                if (hostLower.contains(brandName)) {
                    brandKeywords.add(brandName);
                }

                int dist = levenshtein(registrableDomain, brandDomain);
                if (dist >= 1 && dist <= 2 && (closestDistance == null || dist < closestDistance)) {
                    closestDistance = dist;
                    closestBrand = brandDomain;
                }
            }
        }

        List<Finding> findings = buildFindings(hasUserInfoTrick, ipBased, punycode, suspiciousTld,
                subdomainDepth, brandKeywords, closestBrand, closestDistance);

        return new PhishingCheckResponse(true, raw, scheme, host, ipBased, punycode, hasUserInfoTrick,
                suspiciousTld, subdomainDepth, brandKeywords, closestBrand, closestDistance, findings);
    }

    private List<Finding> buildFindings(boolean hasUserInfoTrick, boolean ipBased, boolean punycode,
                                         String suspiciousTld, int subdomainDepth, List<String> brandKeywords,
                                         String closestBrand, Integer closestDistance) {
        List<Finding> findings = new ArrayList<>();

        if (hasUserInfoTrick) {
            findings.add(Finding.critical("URL'de \"@\" ile kullanıcı bilgisi (userinfo) kullanılmış — "
                    + "tarayıcıda tanıdık görünen bir adın ardına gerçek (farklı) hedefi gizleme "
                    + "tekniği, klasik bir oltalama yöntemidir."));
        }
        if (ipBased) {
            findings.add(Finding.high("Alan adı yerine doğrudan bir IP adresi kullanılmış — "
                    + "meşru kurumsal siteler neredeyse hiçbir zaman doğrudan IP adresiyle yayın yapmaz."));
        }
        if (punycode) {
            findings.add(Finding.high("Alan adı punycode (xn--) kodlaması içeriyor — görsel olarak "
                    + "tanıdık bir markayı taklit eden Unicode karakterler kullanılmış olabilir."));
        }
        if (suspiciousTld != null) {
            findings.add(Finding.medium("Oltalama kampanyalarında sık kullanılan bir üst düzey alan adı: ."
                    + suspiciousTld));
        }
        if (subdomainDepth > MAX_SUBDOMAIN_DEPTH) {
            findings.add(Finding.medium(subdomainDepth + " seviyeli aşırı derin bir alt alan adı yapısı — "
                    + "bir markayı alt alan adı içine gizleme taktiği olabilir."));
        }
        if (closestBrand != null) {
            findings.add(Finding.critical("Alan adı \"" + closestBrand + "\" markasına çok benziyor "
                    + "(düzenleme mesafesi: " + closestDistance + ") ama tam eşleşmiyor — typosquatting olabilir."));
        }
        if (!brandKeywords.isEmpty()) {
            findings.add(Finding.high("Alan adında şu marka isim(ler)i geçiyor ama bu markanın resmi "
                    + "alan adı değil: " + String.join(", ", brandKeywords)));
        }

        if (findings.isEmpty()) {
            findings.add(Finding.low("Belirgin bir oltalama belirtisi bulunamadı. "
                    + "Yine de bağlantıya tıklamadan önce alan adını dikkatle kontrol edin."));
        }

        return findings;
    }

    /** Klasik dinamik programlama ile duzenleme (Levenshtein) mesafesi. */
    private int levenshtein(String a, String b) {
        int[][] dp = new int[a.length() + 1][b.length() + 1];
        for (int i = 0; i <= a.length(); i++) dp[i][0] = i;
        for (int j = 0; j <= b.length(); j++) dp[0][j] = j;

        for (int i = 1; i <= a.length(); i++) {
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                dp[i][j] = Math.min(Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1), dp[i - 1][j - 1] + cost);
            }
        }
        return dp[a.length()][b.length()];
    }
}
