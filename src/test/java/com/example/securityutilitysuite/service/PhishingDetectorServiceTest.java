package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.PhishingCheckRequest;
import com.example.securityutilitysuite.dto.PhishingCheckResponse;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PhishingDetectorServiceTest {

    private final PhishingDetectorService service = new PhishingDetectorService();

    @Test
    void mesruMarkaSitesiTemizCikar() {
        PhishingCheckResponse r = service.analyze(new PhishingCheckRequest("https://www.google.com/search"));

        assertThat(r.parsed()).isTrue();
        assertThat(r.ipBased()).isFalse();
        assertThat(r.punycode()).isFalse();
        assertThat(r.closestBrandMatch()).isNull();
        assertThat(r.findings()).anyMatch(f -> f.severity().equals("LOW"));
    }

    @Test
    void typosquattingTespitEdilir() {
        // "google.com" -> "gooogle.com": tek harf eklenmis, duzenleme mesafesi 1
        PhishingCheckResponse r = service.analyze(new PhishingCheckRequest("http://gooogle.com/login"));

        assertThat(r.closestBrandMatch()).isEqualTo("google.com");
        assertThat(r.closestBrandDistance()).isEqualTo(1);
        assertThat(r.findings()).anyMatch(f -> f.severity().equals("CRITICAL") && f.message().contains("typosquatting"));
    }

    @Test
    void ipTabanliAdresYuksekBulguUretir() {
        PhishingCheckResponse r = service.analyze(new PhishingCheckRequest("http://192.168.45.12/wp-login"));

        assertThat(r.ipBased()).isTrue();
        assertThat(r.findings()).anyMatch(f -> f.severity().equals("HIGH") && f.message().contains("IP adresi"));
    }

    @Test
    void punycodeTespitEdilir() {
        PhishingCheckResponse r = service.analyze(new PhishingCheckRequest("http://xn--pypal-4ve.com/"));

        assertThat(r.punycode()).isTrue();
        assertThat(r.findings()).anyMatch(f -> f.severity().equals("HIGH") && f.message().contains("punycode"));
    }

    @Test
    void supheliTldBulunur() {
        PhishingCheckResponse r = service.analyze(new PhishingCheckRequest("http://free-gift-cards.top/claim"));

        assertThat(r.suspiciousTld()).isEqualTo("top");
        assertThat(r.findings()).anyMatch(f -> f.severity().equals("MEDIUM") && f.message().contains(".top"));
    }

    @Test
    void asiriDerinAltAlanAdiBulgusuUretir() {
        PhishingCheckResponse r = service.analyze(
                new PhishingCheckRequest("http://secure.login.account.verify.example-evil.com/"));

        assertThat(r.subdomainDepth()).isGreaterThan(3);
        assertThat(r.findings()).anyMatch(f -> f.severity().equals("MEDIUM") && f.message().contains("alt alan adı"));
    }

    @Test
    void markaAdiKokAlanAdindaDegilseBulguUretir() {
        PhishingCheckResponse r = service.analyze(new PhishingCheckRequest("http://paypal.verify-account-now.ru/"));

        assertThat(r.brandKeywordsFound()).contains("paypal");
        assertThat(r.findings()).anyMatch(f -> f.severity().equals("HIGH") && f.message().contains("paypal"));
    }

    @Test
    void userInfoHilesiCriticalUretir() {
        PhishingCheckResponse r = service.analyze(new PhishingCheckRequest("http://google.com@evil-site.ru/"));

        assertThat(r.hasUserInfoTrick()).isTrue();
        assertThat(r.findings()).anyMatch(f -> f.severity().equals("CRITICAL") && f.message().contains("@"));
    }

    @Test
    void gecersizUrlParsedFalseDoner() {
        PhishingCheckResponse r = service.analyze(new PhishingCheckRequest("::::gecersiz-url::::"));

        assertThat(r.parsed()).isFalse();
    }

    @Test
    void semasizUrlOtomatikTamamlanir() {
        PhishingCheckResponse r = service.analyze(new PhishingCheckRequest("google.com"));

        assertThat(r.parsed()).isTrue();
        assertThat(r.host()).isEqualTo("google.com");
    }
}
