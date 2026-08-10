package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.Finding;
import com.example.securityutilitysuite.dto.JwtAnalyzeRequest;
import com.example.securityutilitysuite.dto.JwtAnalyzeResponse;
import com.example.securityutilitysuite.dto.JwtClaim;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * JWT Token Analyzer.
 *
 * Tasarim notlari:
 * - Bu bir DOGRULAYICI degil, bir ANALIZ aracidir: token'i imzasiz da olsa
 *   coz up header/payload'i gosterir — cunku amac, gelistiricinin/analistin
 *   bir token'in TASIDIGI VERIYI ve YAPISAL RISKLERI gormesidir. Imza
 *   dogrulama yalnizca kullanici acikca bir "secret" girdiginde ve algoritma
 *   HMAC ailesindense (HS256/384/512) yapilir.
 * - "alg: none" ozel olarak CRITICAL isaretlenir: bu, JWT kutuphanelerinde
 *   bilinen klasik bir istismar sinifidir (saldirgan header'i "none" yapip
 *   imza segmentini bosaltarak imza dogrulamasini atlatabilir, eger sunucu
 *   taraf bunu reddetmiyorsa).
 * - RS/ES gibi asimetrik algoritmalar icin imza dogrulama v1 kapsaminda
 *   desteklenmiyor (ortak anahtar/sertifika girisi gerektirir); bu durumda
 *   kullaniciya acik bir LOW bulgu ile bildirilir, sessizce atlanmaz.
 */
@Service
public class JwtService {

    private static final Set<String> HMAC_ALGS = Set.of("HS256", "HS384", "HS512");
    private static final Map<String, String> HMAC_JAVA_NAME = Map.of(
            "HS256", "HmacSHA256",
            "HS384", "HmacSHA384",
            "HS512", "HmacSHA512"
    );

    private final ObjectMapper mapper = JsonMapper.builder().build();

    public JwtAnalyzeResponse analyze(JwtAnalyzeRequest request) {
        String token = request.token() == null ? "" : request.token().trim();
        if (token.isEmpty()) {
            return JwtAnalyzeResponse.invalid("Token boş olamaz");
        }

        String[] parts = token.split("\\.", -1);
        if (parts.length != 2 && parts.length != 3) {
            return JwtAnalyzeResponse.invalid(
                    "Geçersiz JWT yapısı: nokta ile ayrılmış 3 bölüm bekleniyor (header.payload.signature), "
                            + parts.length + " bölüm bulundu");
        }

        JsonNode headerNode;
        JsonNode payloadNode;
        String headerJson;
        String payloadJson;
        try {
            byte[] headerBytes = decodeBase64Url(parts[0]);
            byte[] payloadBytes = decodeBase64Url(parts[1]);
            headerNode = mapper.readTree(headerBytes);
            payloadNode = mapper.readTree(payloadBytes);
            headerJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(headerNode);
            payloadJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(payloadNode);
        } catch (Exception ex) {
            return JwtAnalyzeResponse.invalid(
                    "Header veya payload çözülemedi: Base64URL ya da JSON biçimi geçersiz");
        }

        String algorithm = textOrNull(headerNode, "alg");
        String type = textOrNull(headerNode, "typ");

        List<JwtClaim> claims = new ArrayList<>();
        Map<String, Object> payloadMap = mapper.convertValue(payloadNode, Map.class);
        for (Map.Entry<String, Object> entry : payloadMap.entrySet()) {
            claims.add(new JwtClaim(entry.getKey(), String.valueOf(entry.getValue())));
        }

        LocalDateTime issuedAt = epochClaim(payloadNode, "iat");
        LocalDateTime expiresAt = epochClaim(payloadNode, "exp");
        LocalDateTime notBefore = epochClaim(payloadNode, "nbf");
        boolean expired = expiresAt != null && expiresAt.isBefore(LocalDateTime.now());

        boolean signatureProvided = parts.length == 3 && !parts[2].isEmpty();

        boolean signatureChecked = false;
        Boolean signatureValid = null;

        List<Finding> findings = new ArrayList<>();

        if (algorithm != null && algorithm.equalsIgnoreCase("none")) {
            findings.add(Finding.critical(
                    "İmza algoritması \"none\" — bu token hiçbir gizli/özel anahtar olmadan "
                            + "herkes tarafından oluşturulabilir. Sunucu tarafı bunu reddetmiyorsa kritik bir açıktır."));
        } else if (!signatureProvided) {
            findings.add(Finding.high(
                    "İmza segmenti boş veya eksik, ancak algoritma \"" + algorithm + "\" olarak belirtilmiş — "
                            + "tutarsız bir token."));
        }

        if (expiresAt == null) {
            findings.add(Finding.medium("\"exp\" claim'i yok — bu token süresiz, hiç geçersiz olmuyor."));
        } else if (expired) {
            findings.add(Finding.high("Token süresi dolmuş (" + expiresAt + ")."));
        }

        if (issuedAt == null) {
            findings.add(Finding.low("\"iat\" (oluşturulma zamanı) claim'i yok."));
        }

        if (notBefore != null && notBefore.isAfter(LocalDateTime.now())) {
            findings.add(Finding.medium("Token henüz geçerlilik başlangıcına (\"nbf\") ulaşmadı."));
        }

        String secret = request.secret() == null ? "" : request.secret().trim();
        if (!secret.isEmpty() && algorithm != null) {
            if (HMAC_ALGS.contains(algorithm.toUpperCase())) {
                signatureChecked = true;
                if (!signatureProvided) {
                    signatureValid = false;
                    findings.add(Finding.high("Doğrulanacak bir imza segmenti yok."));
                } else {
                    try {
                        signatureValid = verifyHmac(parts, algorithm.toUpperCase(), secret);
                        if (!signatureValid) {
                            findings.add(Finding.high(
                                    "İmza, verilen anahtarla eşleşmiyor — token bu anahtarla üretilmemiş "
                                            + "ya da içerik değiştirilmiş."));
                        }
                    } catch (Exception ex) {
                        signatureChecked = false;
                        findings.add(Finding.low("İmza doğrulaması çalıştırılamadı: " + ex.getMessage()));
                    }
                }
            } else {
                findings.add(Finding.low(
                        "\"" + algorithm + "\" algoritması için imza doğrulama v1 kapsamında desteklenmiyor "
                                + "(asimetrik algoritmalar ortak anahtar/sertifika gerektirir)."));
            }
        }

        return new JwtAnalyzeResponse(
                true, null, headerJson, payloadJson, algorithm, type,
                claims, issuedAt, expiresAt, notBefore, expired,
                signatureProvided, signatureChecked, signatureValid, findings
        );
    }

    // ------------------------------------------------------------------
    // Yardimcilar
    // ------------------------------------------------------------------

    private byte[] decodeBase64Url(String segment) {
        String padded = segment;
        int rem = padded.length() % 4;
        if (rem == 2) padded += "==";
        else if (rem == 3) padded += "=";
        else if (rem == 1) throw new IllegalArgumentException("Geçersiz Base64URL uzunluğu");
        return Base64.getUrlDecoder().decode(padded);
    }

    private String textOrNull(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return (v == null || v.isNull()) ? null : v.asText();
    }

    private LocalDateTime epochClaim(JsonNode payload, String field) {
        JsonNode v = payload.get(field);
        if (v == null || !v.isNumber()) {
            return null;
        }
        return LocalDateTime.ofInstant(Instant.ofEpochSecond(v.asLong()), ZoneId.systemDefault());
    }

    private String describeValue(JsonNode node) {
        if (node == null || node.isNull()) return "null";
        if (node.isValueNode()) return node.asText();
        return node.toString();
    }

    /** HMAC (HS256/384/512) imzasini sabit-zamanli karsilastirma ile dogrular. */
    private boolean verifyHmac(String[] parts, String alg, String secret) throws Exception {
        String javaAlg = HMAC_JAVA_NAME.get(alg);
        Mac mac = Mac.getInstance(javaAlg);
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), javaAlg));
        byte[] expected = mac.doFinal((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
        byte[] actual = decodeBase64Url(parts[2]);
        return MessageDigest.isEqual(expected, actual);
    }
}
