package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.Finding;
import com.example.securityutilitysuite.dto.SshAnalyzeRequest;
import com.example.securityutilitysuite.dto.SshAnalyzeResponse;
import com.example.securityutilitysuite.dto.SshIpSummary;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SSH Brute-Force Blocker.
 *
 * Tasarim notlari:
 * - Yalnizca standart OpenSSH syslog satirlarini ("sshd[...]:" iceren) tanir.
 *   "Failed password for ..." satiri, basarisiz bir denemenin TEK yetkili
 *   kaniti olarak sayilir. Ayni denemeyle ilgili "Invalid user ..." gibi ON
 *   satirlar (OpenSSH ayni denemeyi bazen 2-3 satirla loglar) ayrica
 *   SAYILMAZ — aksi halde tek bir deneme 2-3 kez sayilip esik yapay olarak
 *   erken asilirdi.
 * - "Accepted ..." satirlari basari olarak isaretlenir. Bir IP hem basarisiz
 *   denemelere hem de sonrasinda bir basariya sahipse (succeededAfterFailures),
 *   bu ozellikle onemlidir: ya kaba kuvvetle hesap ele gecirilmis, ya da
 *   mesru bir kullanici birkac kez sasirdiktan sonra giris yapmistir — ikisini
 *   ayirt etmek log'un kendisinden mumkun degildir, bu yuzden CRITICAL olarak
 *   isaretlenip insan degerlendirmesine birakilir.
 * - Bu modul kural ONERIR, hicbir ates duvari/engelleme kuralini kendisi
 *   UYGULAMAZ — yalnizca bir "ufw deny" komut metni uretir, kullanici bunu
 *   kendi sorumlulugunda calistirir.
 */
@Service
public class SshBruteForceService {

    private static final int DEFAULT_THRESHOLD = 5;
    private static final int MAX_USERNAMES_SHOWN = 10;

    private static final Pattern TIMESTAMP = Pattern.compile("^(\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})");

    private static final Pattern FAILED = Pattern.compile(
            "Failed password for (?:invalid user )?(\\S+) from ([0-9a-fA-F:.]+) port \\d+");

    private static final Pattern ACCEPTED = Pattern.compile(
            "Accepted (?:password|publickey) for (\\S+) from ([0-9a-fA-F:.]+) port \\d+");

    public SshAnalyzeResponse analyze(SshAnalyzeRequest request) {
        String content = request.logContent() == null ? "" : request.logContent();
        int threshold = (request.threshold() == null || request.threshold() < 1)
                ? DEFAULT_THRESHOLD : request.threshold();

        String[] lines = content.isBlank() ? new String[0] : content.split("\\R");

        Map<String, IpAccumulator> byIp = new LinkedHashMap<>();
        int matchedLines = 0;

        for (String line : lines) {
            String ts = extractTimestamp(line);

            Matcher failedM = FAILED.matcher(line);
            if (failedM.find()) {
                matchedLines++;
                String username = failedM.group(1);
                String ip = failedM.group(2);
                IpAccumulator acc = byIp.computeIfAbsent(ip, k -> new IpAccumulator());
                acc.failedAttempts++;
                acc.usernames.add(username);
                acc.touch(ts);
                continue;
            }

            Matcher acceptedM = ACCEPTED.matcher(line);
            if (acceptedM.find()) {
                matchedLines++;
                String ip = acceptedM.group(2);
                IpAccumulator acc = byIp.computeIfAbsent(ip, k -> new IpAccumulator());
                if (acc.failedAttempts > 0) {
                    acc.succeededAfterFailures = true;
                }
                acc.touch(ts);
            }
        }

        List<SshIpSummary> summaries = new ArrayList<>();
        for (Map.Entry<String, IpAccumulator> e : byIp.entrySet()) {
            IpAccumulator acc = e.getValue();
            boolean recommendBlock = acc.failedAttempts >= threshold;
            List<String> usernames = acc.usernames.stream().limit(MAX_USERNAMES_SHOWN).toList();

            summaries.add(new SshIpSummary(
                    e.getKey(),
                    acc.failedAttempts,
                    acc.succeededAfterFailures,
                    usernames,
                    acc.firstSeen,
                    acc.lastSeen,
                    recommendBlock,
                    recommendBlock ? "sudo ufw deny from " + e.getKey() + " to any port 22" : null
            ));
        }

        summaries.sort((a, b) -> Integer.compare(b.failedAttempts(), a.failedAttempts()));

        List<Finding> findings = buildFindings(summaries, lines.length, matchedLines, threshold);

        return new SshAnalyzeResponse(lines.length, matchedLines, threshold, summaries, findings);
    }

    private List<Finding> buildFindings(List<SshIpSummary> summaries, int totalLines, int matchedLines, int threshold) {
        List<Finding> findings = new ArrayList<>();

        if (totalLines > 0 && matchedLines == 0) {
            findings.add(Finding.low(
                    "Girdi içinde tanınan bir SSH log satırı bulunamadı. Standart OpenSSH syslog "
                            + "biçimi (\"sshd[...]: Failed password ...\" / \"Accepted ...\") bekleniyor."));
            return findings;
        }

        for (SshIpSummary s : summaries) {
            if (s.succeededAfterFailures() && s.failedAttempts() >= 3) {
                findings.add(Finding.critical(
                        s.ip() + " adresi " + s.failedAttempts() + " başarısız denemeden sonra BAŞARILI "
                                + "giriş yaptı — hesap ele geçirilmiş olabilir, acilen doğrulanmalı."));
            } else if (s.recommendBlock()) {
                findings.add(Finding.high(
                        s.ip() + " adresinden " + s.failedAttempts() + " başarısız giriş denemesi "
                                + "(eşik: " + threshold + ") — engelleme önerilir."));
            }
        }

        if (findings.isEmpty()) {
            findings.add(Finding.low("Eşiği aşan veya şüpheli bir kaynak IP tespit edilmedi."));
        }

        return findings;
    }

    private String extractTimestamp(String line) {
        Matcher m = TIMESTAMP.matcher(line);
        return m.find() ? m.group(1) : null;
    }

    private static class IpAccumulator {
        int failedAttempts = 0;
        boolean succeededAfterFailures = false;
        Set<String> usernames = new LinkedHashSet<>();
        String firstSeen;
        String lastSeen;

        void touch(String ts) {
            if (ts == null) return;
            if (firstSeen == null) firstSeen = ts;
            lastSeen = ts;
        }
    }
}
