package com.example.securityutilitysuite.service;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Bu testler AGA HIC BAGLANMAZ — WebVulnScannerService'in saf (network'ten
 * bagimsiz) tespit fonksiyonlarini dogrudan cagirir. Gercek HTTP akisi
 * (scan()) bu ortamda test edilemez (NetworkGuard localhost/test sunucularini
 * kasitli olarak reddeder ve gercek bir hedefe istek atmak testleri
 * agdan/zamandan bagimsiz olma ilkesini bozar) — bu yuzden tespit mantigi
 * kasitli olarak paket-ozel static metodlara ayristirilip izole test edildi.
 */
class WebVulnScannerServiceTest {

    @Test
    void kaciriliMayanXssPayloadYansimaOlarakTespitEdilir() {
        String payload = "<script>alert('XSS')</script>";
        String body = "<html><body>Arama sonucu: " + payload + "</body></html>";

        assertThat(WebVulnScannerService.xssReflected(body, payload)).isTrue();
    }

    @Test
    void htmlKacirilmisPayloadTespitEdilmez() {
        String payload = "<script>alert('XSS')</script>";
        String escaped = "&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;";
        String body = "<html><body>Arama sonucu: " + escaped + "</body></html>";

        assertThat(WebVulnScannerService.xssReflected(body, payload)).isFalse();
    }

    @Test
    void ikinciXssPayloadTuruDeTespitEdilir() {
        String payload = "\"><img src=x onerror=alert(1)>";
        String body = "<input value=\"" + payload + "\">";

        assertThat(WebVulnScannerService.xssReflected(body, payload)).isTrue();
    }

    @Test
    void bosYanitYansimaOlarakSayilmaz() {
        assertThat(WebVulnScannerService.xssReflected(null, "<script>x</script>")).isFalse();
        assertThat(WebVulnScannerService.xssReflected("", "<script>x</script>")).isFalse();
    }

    @Test
    void bilinenMysqlHatasiTespitEdilir() {
        String body = "Warning: mysql_fetch_array() expects parameter 1 to be resource";
        assertThat(WebVulnScannerService.sqlErrorDetected(body)).isTrue();
    }

    @Test
    void bilinenPostgresHatasiTespitEdilir() {
        String body = "org.postgresql.util.PSQLException: syntax error at or near";
        assertThat(WebVulnScannerService.sqlErrorDetected(body)).isTrue();
    }

    @Test
    void normalYanitHataOlarakIsaretlenmez() {
        String body = "<html><body><h1>Sonuç bulunamadı</h1></body></html>";
        assertThat(WebVulnScannerService.sqlErrorDetected(body)).isFalse();
    }

    @Test
    void booleanTabanliSqliSuphesiBelirginFarktaTespitEdilir() {
        // dogru kosul ~baseline'a yakin (5000 -> 5010), yanlis kosul cok kisa
        // (800) — klasik "sonuc var / sonuc yok" boolean-tabanli SQLi kalibi
        assertThat(WebVulnScannerService.booleanSqliSuspected(5000, 5010, 800)).isTrue();
    }

    @Test
    void tutarliUzunluklarSqliOlarakIsaretlenmez() {
        assertThat(WebVulnScannerService.booleanSqliSuspected(5000, 5010, 4990)).isFalse();
    }

    @Test
    void sifirBaselineGuvenliSekildeFalseDoner() {
        assertThat(WebVulnScannerService.booleanSqliSuspected(0, 100, 5)).isFalse();
    }

    @Test
    void kucukMutlakFarkSqliOlarakIsaretlenmez() {
        // oranlar esigi gecse bile mutlak fark cok kucukse (kisa baseline'da
        // birkac baytlik oynama) yanlis pozitif olmamali
        assertThat(WebVulnScannerService.booleanSqliSuspected(50, 50, 34)).isFalse();
    }
}
