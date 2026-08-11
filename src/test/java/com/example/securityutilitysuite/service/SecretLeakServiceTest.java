package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.SecretScanRequest;
import com.example.securityutilitysuite.dto.SecretScanResponse;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SecretLeakServiceTest {

    private final SecretLeakService service = new SecretLeakService();

    @Test
    void awsAccessKeyTespitEdilirVeMaskelenir() {
        String content = "aws_key = \"AKIAABCDEFGHIJKLMNOP\"";
        SecretScanResponse r = service.scan(new SecretScanRequest(content));

        assertThat(r.leakCount()).isEqualTo(1);
        assertThat(r.leaks().get(0).type()).isEqualTo("AWS Access Key ID");
        assertThat(r.leaks().get(0).severity()).isEqualTo("CRITICAL");
        // Ham anahtar hicbir zaman aynen donmemeli
        assertThat(r.leaks().get(0).maskedValue()).doesNotContain("AKIAABCDEFGHIJKLMNOP");
        assertThat(r.leaks().get(0).maskedValue()).contains("…");
    }

    @Test
    void githubTokenSatirNumarasiylaBirlikteBulunur() {
        String content = "satir1\nsatir2\nconst token = \"ghp_" + "a".repeat(36) + "\";\nsatir4";
        SecretScanResponse r = service.scan(new SecretScanRequest(content));

        assertThat(r.leaks()).hasSize(1);
        assertThat(r.leaks().get(0).type()).isEqualTo("GitHub Personal Access Token");
        assertThat(r.leaks().get(0).line()).isEqualTo(3);
    }

    @Test
    void ozelAnahtarBlokuCriticalUretir() {
        String content = "-----BEGIN RSA PRIVATE KEY-----\nMIIExampleNotARealKey\n-----END RSA PRIVATE KEY-----";
        SecretScanResponse r = service.scan(new SecretScanRequest(content));

        assertThat(r.findings()).anyMatch(f -> f.severity().equals("CRITICAL")
                && f.message().contains("Özel Anahtar"));
    }

    @Test
    void veritabaniBaglantiParolasiniYakalar() {
        String content = "DATABASE_URL=postgres://admin:CokGizliParola123@db.example.com:5432/app";
        SecretScanResponse r = service.scan(new SecretScanRequest(content));

        assertThat(r.leaks()).anyMatch(l -> l.type().contains("Veritabanı"));
    }

    @Test
    void ayniTurdenBirdenFazlaSizintiTekBulguyaGruplanır() {
        String content = "api_key=\"abcd1234efgh\"\napi_key=\"ijkl5678mnop\"\napi_key=\"qrst9012uvwx\"";
        SecretScanResponse r = service.scan(new SecretScanRequest(content));

        long genelAtamaBulgusu = r.findings().stream()
                .filter(f -> f.message().contains("Genel Anahtar/Parola"))
                .count();
        assertThat(genelAtamaBulgusu).isEqualTo(1);
        assertThat(r.leakCount()).isEqualTo(3);
    }

    @Test
    void temizMetinBulguUretmez() {
        SecretScanResponse r = service.scan(new SecretScanRequest("public class Foo { void bar() {} }"));

        assertThat(r.leakCount()).isZero();
        assertThat(r.findings()).anyMatch(f -> f.severity().equals("LOW"));
    }

    @Test
    void onIkiKarakterAltiTamamenMaskelenir() {
        // 11 karakter — esik 12'nin ALTINDA, tamamen yildizlanmali
        String content = "token=\"abcdefghijk\""; // 11 karakter
        SecretScanResponse r = service.scan(new SecretScanRequest(content));

        assertThat(r.leaks()).hasSize(1);
        assertThat(r.leaks().get(0).maskedValue()).isEqualTo("*".repeat(11));
    }

    @Test
    void onIkiKarakterVeUzeriKismenMaskelenir() {
        // 13 karakter — esigin USTUNDE, kismi maskeleme (ilk4…son4)
        String content = "token=\"abcdefghijklm\""; // 13 karakter
        SecretScanResponse r = service.scan(new SecretScanRequest(content));

        assertThat(r.leaks()).hasSize(1);
        String masked = r.leaks().get(0).maskedValue();
        assertThat(masked).startsWith("abcd").endsWith("jklm").contains("…");
        assertThat(masked).doesNotContain("abcdefghijklm");
    }

    @Test
    void jenerikKalipBulgusuDogrulamaNotuIcerir() {
        String content = "password: \"degistirin123\"";
        SecretScanResponse r = service.scan(new SecretScanRequest(content));

        assertThat(r.findings()).anyMatch(f ->
                f.message().contains("Genel Anahtar/Parola") && f.message().contains("elle doğrulanmalı"));
    }

    @Test
    void kesinKaliplarJenerikNotAlmaz() {
        String content = "AKIAABCDEFGHIJKLMNOP";
        SecretScanResponse r = service.scan(new SecretScanRequest(content));

        assertThat(r.findings()).anyMatch(f -> f.message().contains("AWS Access Key"));
        assertThat(r.findings()).noneMatch(f -> f.message().contains("AWS Access Key") && f.message().contains("elle doğrulanmalı"));
    }
}
