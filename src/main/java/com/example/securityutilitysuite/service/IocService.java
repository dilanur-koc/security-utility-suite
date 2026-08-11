package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.Finding;
import com.example.securityutilitysuite.dto.IocExtractRequest;
import com.example.securityutilitysuite.dto.IocExtractResponse;
import com.example.securityutilitysuite.dto.IocItem;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Threat Intel (IOC) Extractor.
 *
 * ONEMLI KAPSAM NOTU: Bu modul canli bir tehdit istihbarati servisine
 * (VirusTotal, AbuseIPDB, vb.) SORGU ATMAZ — boyle bir entegrasyon API
 * anahtari yonetimi, oran sinirlama ve harici bir servise bagimlilik
 * getirir. Bunun yerine modul, bir metin icindeki gostergeleri (IP, domain,
 * URL, hash, e-posta) CIKARIR, siniflandirir ve "defanged" (etkisizlestirilmis,
 * orn. "1[.]2[.]3[.]4") gosterimleri normal hale getirir — bir analistin
 * bir raporu hizlica tarayip gostergeleri listelemesini saglar. Bulunanlarin
 * gercekten kotu amacli olup olmadigi kullanicinin kendi tehdit istihbarati
 * araclariyla dogrulamasi gereken ayri bir adimdir; bu, arayuzde ve
 * bulgularda acikca belirtilir.
 */
@Service
public class IocService {

    private record Range(int start, int end) {
        boolean overlaps(Range o) {
            return start < o.end && o.start < end;
        }
    }

    private static final Pattern SHA256 = Pattern.compile("\\b[a-fA-F0-9]{64}\\b");
    private static final Pattern SHA1 = Pattern.compile("\\b[a-fA-F0-9]{40}\\b");
    private static final Pattern MD5 = Pattern.compile("\\b[a-fA-F0-9]{32}\\b");
    private static final Pattern EMAIL = Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,24}\\b");
    private static final Pattern URL = Pattern.compile("\\bhttps?://[^\\s\"'<>]+");
    private static final Pattern IPV4 = Pattern.compile(
            "\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b");
    private static final Pattern IPV6 = Pattern.compile(
            "\\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\\b");
    private static final Pattern DOMAIN = Pattern.compile(
            "\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,24}\\b");

    public IocExtractResponse extract(IocExtractRequest request) {
        String raw = request.content() == null ? "" : request.content();
        Defanged d = refang(raw);
        String content = d.text();

        List<Range> consumed = new ArrayList<>();
        List<IocItem> items = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();

        extractInto(content, SHA256, "SHA256", consumed, items, seen, this::hashNote);
        extractInto(content, SHA1, "SHA1", consumed, items, seen, this::hashNote);
        extractInto(content, MD5, "MD5", consumed, items, seen, this::hashNote);
        extractInto(content, EMAIL, "EMAIL", consumed, items, seen, v -> "e-posta adresi");
        extractInto(content, URL, "URL", consumed, items, seen, v -> "tam URL");
        extractInto(content, IPV4, "IPV4", consumed, items, seen, this::ipv4Note);
        extractInto(content, IPV6, "IPV6", consumed, items, seen, v -> "IPv6 adresi");
        extractInto(content, DOMAIN, "DOMAIN", consumed, items, seen, v -> "alan adı");

        List<Finding> findings = buildFindings(items, d.count());

        return new IocExtractResponse(d.count(), items, findings);
    }

    private interface NoteFn { String apply(String value); }

    private void extractInto(String content, Pattern pattern, String type, List<Range> consumed,
                              List<IocItem> items, Set<String> seen, NoteFn noteFn) {
        Matcher m = pattern.matcher(content);
        while (m.find()) {
            Range r = new Range(m.start(), m.end());
            if (consumed.stream().anyMatch(r::overlaps)) continue;

            String value = m.group();
            String dedupeKey = type + "|" + value;
            if (!seen.add(dedupeKey)) {
                consumed.add(r);
                continue;
            }
            items.add(new IocItem(type, value, noteFn.apply(value)));
            consumed.add(r);
        }
    }

    private String hashNote(String value) {
        return switch (value.length()) {
            case 32 -> "MD5 özeti";
            case 40 -> "SHA1 özeti";
            case 64 -> "SHA256 özeti";
            default -> "özet (hash)";
        };
    }

    private String ipv4Note(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return "genel (public) adres";
        int a = Integer.parseInt(parts[0]);
        int b = Integer.parseInt(parts[1]);

        if (a == 10) return "özel/dahili adres (RFC1918)";
        if (a == 172 && b >= 16 && b <= 31) return "özel/dahili adres (RFC1918)";
        if (a == 192 && b == 168) return "özel/dahili adres (RFC1918)";
        if (a == 127) return "loopback adresi";
        if (a == 169 && b == 254) return "link-local adres";
        return "genel (public) adres";
    }

    private List<Finding> buildFindings(List<IocItem> items, int defangedCount) {
        List<Finding> findings = new ArrayList<>();

        if (defangedCount > 0) {
            findings.add(Finding.low(defangedCount + " adet etkisizleştirilmiş (defanged) gösterge normal biçime çevrildi."));
        }

        if (items.isEmpty()) {
            findings.add(Finding.low("Metin içinde tanınan bir IOC (IP, alan adı, URL, hash, e-posta) bulunamadı."));
            return findings;
        }

        long privateIpCount = items.stream()
                .filter(i -> i.type().equals("IPV4") && i.note().contains("özel/dahili"))
                .count();
        if (privateIpCount > 0) {
            findings.add(Finding.low(privateIpCount + " adet özel/dahili IP adresi bulundu — bunlar genel "
                    + "tehdit istihbaratı beslemeleriyle eşleşmez."));
        }

        findings.add(Finding.medium(items.size() + " gösterge çıkarıldı. Bu modül yalnızca çıkarma ve "
                + "sınıflandırma yapar; canlı bir tehdit istihbaratı servisine (VirusTotal, AbuseIPDB vb.) "
                + "sorgu ATMAZ — bulunan göstergeleri kendi araçlarınızla çapraz kontrol edin."));

        return findings;
    }

    // ------------------------------------------------------------------
    // Defang / refang
    // ------------------------------------------------------------------

    private record Defanged(String text, int count) {
    }

    private Defanged refang(String text) {
        int[] count = {0};
        String out = text;

        out = replaceCounting(out, "\\[\\.\\]", ".", count);
        out = replaceCounting(out, "\\(\\.\\)", ".", count);
        out = replaceCounting(out, "\\[dot\\]", ".", count);
        out = replaceCounting(out, "(?i)hxxp", "http", count);
        out = replaceCounting(out, "\\[:\\]", ":", count);
        out = replaceCounting(out, "\\[at\\]", "@", count);
        out = replaceCounting(out, "\\(at\\)", "@", count);

        return new Defanged(out, count[0]);
    }

    private String replaceCounting(String text, String regex, String replacement, int[] counter) {
        Matcher m = Pattern.compile(regex).matcher(text);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            counter[0]++;
            m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        return sb.toString();
    }
}
