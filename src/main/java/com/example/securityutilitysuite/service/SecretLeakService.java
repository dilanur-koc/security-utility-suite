package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.Finding;
import com.example.securityutilitysuite.dto.SecretLeak;
import com.example.securityutilitysuite.dto.SecretScanRequest;
import com.example.securityutilitysuite.dto.SecretScanResponse;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Git & Secret Leak Finder.
 *
 * Tasarim notlari:
 * - Kalip listesi taninmis ac gizli anahtar formatlarini (AWS, GitHub, Slack,
 *   Stripe, Google, ozel anahtar bloklari) ve genel "anahtar = deger" tarzi
 *   atamalari kapsar. Genel kalip yanlis pozitif uretebilir (orn. degisken
 *   adinda "token" gecen zararsiz bir kod) — bu kasitli bir tercih: bir
 *   sizinti bulucuda kacirmak (false negative), fazladan uyarmaktan
 *   (false positive) daha pahalidir.
 * - Bulunan HICBIR sizinti ham haliyle donmez; sadece kismen maskelenmis
 *   hali gosterilir. Amac "burada bir sey var, kaynagini kontrol et"
 *   demektir, secret'i tekrar tasimaci olarak kullanmak degildir.
 * - Bulgular (findings) turlere gore GRUPLANIR (her ornek icin ayri degil);
 *   aksi halde 50 tane ayni turden sizinti 50 ayri bulgu satiri olur ve
 *   asil onemli olanlar gozden kacar. Ayrintili liste "leaks" alaninda
 *   tum orneklerle birlikte gelir.
 */
@Service
public class SecretLeakService {

    private record SecretPattern(String type, Pattern pattern, String severity, int valueGroup) {
    }

    private final List<SecretPattern> patterns = List.of(
            new SecretPattern("Özel Anahtar Bloğu (Private Key)",
                    Pattern.compile("-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
                    "CRITICAL", 0),
            new SecretPattern("AWS Access Key ID",
                    Pattern.compile("\\bAKIA[0-9A-Z]{16}\\b"),
                    "CRITICAL", 0),
            new SecretPattern("AWS Secret Access Key",
                    Pattern.compile("(?i)aws_secret_access_key\\s*[:=]\\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
                    "CRITICAL", 1),
            new SecretPattern("GitHub Personal Access Token",
                    Pattern.compile("\\bghp_[A-Za-z0-9]{36}\\b"),
                    "CRITICAL", 0),
            new SecretPattern("GitHub OAuth/App Token",
                    Pattern.compile("\\b(?:gho|ghu|ghs)_[A-Za-z0-9]{36}\\b"),
                    "CRITICAL", 0),
            new SecretPattern("Slack Token",
                    Pattern.compile("\\bxox[baprs]-[0-9A-Za-z-]{10,48}\\b"),
                    "CRITICAL", 0),
            new SecretPattern("Slack Webhook URL",
                    Pattern.compile("https://hooks\\.slack\\.com/services/[A-Za-z0-9/]+"),
                    "HIGH", 0),
            new SecretPattern("Stripe Canlı (Live) Anahtarı",
                    Pattern.compile("\\bsk_live_[0-9a-zA-Z]{16,}\\b"),
                    "CRITICAL", 0),
            new SecretPattern("Stripe Test Anahtarı",
                    Pattern.compile("\\bsk_test_[0-9a-zA-Z]{16,}\\b"),
                    "MEDIUM", 0),
            new SecretPattern("Google API Key",
                    Pattern.compile("\\bAIza[0-9A-Za-z\\-_]{35}\\b"),
                    "HIGH", 0),
            new SecretPattern("Veritabanı Bağlantı Dizisinde Parola",
                    Pattern.compile("(?i)\\b(mongodb(\\+srv)?|postgres(ql)?|mysql|redis)://[^:/\\s]+:([^@/\\s]+)@"),
                    "HIGH", 4),
            new SecretPattern("Olası JWT",
                    Pattern.compile("\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b"),
                    "MEDIUM", 0),
            new SecretPattern("Genel Anahtar/Parola Ataması",
                    Pattern.compile("(?i)\\b(api[_-]?key|secret|token|password|passwd|pwd)\\s*[:=]\\s*['\"]([A-Za-z0-9\\-_/+=]{8,})['\"]"),
                    "MEDIUM", 2)
    );

    public SecretScanResponse scan(SecretScanRequest request) {
        String content = request.content() == null ? "" : request.content();
        String[] lines = content.isEmpty() ? new String[0] : content.split("\\R", -1);

        List<SecretLeak> leaks = new ArrayList<>();
        List<int[]> consumed = new ArrayList<>();

        for (SecretPattern sp : patterns) {
            Matcher m = sp.pattern().matcher(content);
            while (m.find()) {
                int matchStart = m.start();
                int matchEnd = m.end();
                boolean overlaps = consumed.stream()
                        .anyMatch(r -> matchStart < r[1] && r[0] < matchEnd);
                if (overlaps) continue;

                String raw = sp.valueGroup() == 0 ? m.group() : m.group(sp.valueGroup());
                if (raw == null || raw.isBlank()) continue;
                int lineNo = lineNumberAt(content, m.start());
                leaks.add(new SecretLeak(sp.type(), sp.severity(), lineNo, mask(raw)));
                consumed.add(new int[]{matchStart, matchEnd});
            }
        }

        leaks.sort((a, b) -> Integer.compare(a.line(), b.line()));

        List<Finding> findings = buildFindings(leaks);

        return new SecretScanResponse(lines.length, leaks.size(), leaks, findings);
    }

    private List<Finding> buildFindings(List<SecretLeak> leaks) {
        List<Finding> findings = new ArrayList<>();
        if (leaks.isEmpty()) {
            findings.add(Finding.low("Bilinen sızıntı kalıplarından hiçbiri bulunamadı."));
            return findings;
        }

        // Tur -> (siddet, adet, ornek satirlar) olarak grupla
        Map<String, int[]> countBySeverityKey = new LinkedHashMap<>(); // key: type|severity -> {count}
        Map<String, List<Integer>> linesByKey = new LinkedHashMap<>();
        Map<String, String> severityByType = new LinkedHashMap<>();

        for (SecretLeak leak : leaks) {
            String key = leak.type() + "|" + leak.severity();
            countBySeverityKey.merge(key, new int[]{1}, (a, b) -> new int[]{a[0] + 1});
            linesByKey.computeIfAbsent(key, k -> new ArrayList<>()).add(leak.line());
            severityByType.put(key, leak.severity());
        }

        for (Map.Entry<String, int[]> e : countBySeverityKey.entrySet()) {
            String[] parts = e.getKey().split("\\|", 2);
            String type = parts[0];
            String severity = parts[1];
            int count = e.getValue()[0];
            List<Integer> lineNos = linesByKey.get(e.getKey());

            String satirBilgisi = lineNos.stream().anyMatch(l -> l > 0)
                    ? " (satır: " + joinLines(lineNos) + ")"
                    : "";

            String msg = count == 1
                    ? type + " tespit edildi" + satirBilgisi + "."
                    : count + " adet " + type + " tespit edildi" + satirBilgisi + ".";

            findings.add(new Finding(severity, msg));
        }

        return findings;
    }

    private String joinLines(List<Integer> lines) {
        List<Integer> shown = lines.stream().filter(l -> l > 0).distinct().sorted().limit(10).toList();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < shown.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(shown.get(i));
        }
        if (lines.size() > shown.size()) sb.append(", …");
        return sb.toString();
    }

    private int lineNumberAt(String content, int index) {
        int line = 1;
        for (int i = 0; i < index && i < content.length(); i++) {
            if (content.charAt(i) == '\n') line++;
        }
        return line;
    }

    /** Ham secret hicbir zaman aynen dondurulmez; yalnizca kismi/maskelenmis hali. */
    private String mask(String raw) {
        int len = raw.length();
        if (len <= 8) {
            return "*".repeat(len);
        }
        return raw.substring(0, 4) + "…" + raw.substring(len - 4);
    }
}
