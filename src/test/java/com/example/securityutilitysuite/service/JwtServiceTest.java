package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.JwtAnalyzeRequest;
import com.example.securityutilitysuite.dto.JwtAnalyzeResponse;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Gercek imzali JWT'ler test icinde programatik olarak insa edilir —
 * boylece kutuphaneye/harici bir tokene bagimli olunmaz.
 */
class JwtServiceTest {

    private final JwtService service = new JwtService();

    @Test
    void bilinenJwtIoOrnegiDogruCozulurVeImzaDogrulanir() {
        // jwt.io'nun herkese acik ornek token'i: HS256, secret "your-256-bit-secret"
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        JwtAnalyzeResponse r = service.analyze(new JwtAnalyzeRequest(token, "your-256-bit-secret"));

        assertThat(r.valid()).isTrue();
        assertThat(r.algorithm()).isEqualTo("HS256");
        assertThat(r.type()).isEqualTo("JWT");
        assertThat(r.claims()).extracting("name").contains("sub", "name", "iat");
        assertThat(r.signatureChecked()).isTrue();
        assertThat(r.signatureValid()).isTrue();
        // exp claim'i yok -> "sureszi" bulgusu beklenir
        assertThat(r.findings()).anyMatch(f -> f.message().contains("exp"));
    }

    @Test
    void yanlisSecretImzayiGecersizBulur() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        JwtAnalyzeResponse r = service.analyze(new JwtAnalyzeRequest(token, "yanlis-anahtar"));

        assertThat(r.signatureChecked()).isTrue();
        assertThat(r.signatureValid()).isFalse();
        assertThat(r.findings()).anyMatch(f -> f.severity().equals("HIGH"));
    }

    @Test
    void algNoneKritikBulguUretir() {
        String header = b64("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        String payload = b64("{\"sub\":\"saldirgan\"}");
        String token = header + "." + payload + ".";

        JwtAnalyzeResponse r = service.analyze(new JwtAnalyzeRequest(token, null));

        assertThat(r.valid()).isTrue();
        assertThat(r.algorithm()).isEqualTo("none");
        assertThat(r.findings()).anyMatch(f -> f.severity().equals("CRITICAL") && f.message().contains("none"));
    }

    @Test
    void suresiDolmusTokenHighBulguUretir() {
        String header = b64("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        // exp: 1000000000 -> 2001 yili, kesin gecmiste
        String payload = b64("{\"sub\":\"x\",\"exp\":1000000000}");
        String token = header + "." + payload + ".imza-onemli-degil";

        JwtAnalyzeResponse r = service.analyze(new JwtAnalyzeRequest(token, null));

        assertThat(r.valid()).isTrue();
        assertThat(r.expired()).isTrue();
        assertThat(r.findings()).anyMatch(f -> f.severity().equals("HIGH") && f.message().contains("dolmuş"));
    }

    @Test
    void gecerliImzaliTokenSignatureValidTrueDoner() throws Exception {
        String header = b64("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        String payload = b64("{\"sub\":\"test\"}");
        String secret = "cok-guclu-bir-anahtar-2026";

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] sig = mac.doFinal((header + "." + payload).getBytes(StandardCharsets.UTF_8));
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(sig);

        String token = header + "." + payload + "." + signature;

        JwtAnalyzeResponse r = service.analyze(new JwtAnalyzeRequest(token, secret));

        assertThat(r.signatureChecked()).isTrue();
        assertThat(r.signatureValid()).isTrue();
    }

    @Test
    void bozukYapiGecersizOlarakIsaretlenir() {
        JwtAnalyzeResponse r = service.analyze(new JwtAnalyzeRequest("sadece-bir-parca", null));

        assertThat(r.valid()).isFalse();
        assertThat(r.error()).isNotBlank();
    }

    @Test
    void bosTokenGecersizOlarakIsaretlenir() {
        JwtAnalyzeResponse r = service.analyze(new JwtAnalyzeRequest("   ", null));

        assertThat(r.valid()).isFalse();
    }

    private String b64(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
