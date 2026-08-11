package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.IocExtractRequest;
import com.example.securityutilitysuite.dto.IocExtractResponse;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class IocServiceTest {

    private final IocService service = new IocService();

    @Test
    void defangedIpVeUrlNormallestirilir() {
        String content = "Şüpheli sunucu: 203[.]0[.]113[.]5 — hxxp://kotu-site[.]com/yol";
        IocExtractResponse r = service.extract(new IocExtractRequest(content));

        assertThat(r.defangedCount()).isGreaterThan(0);
        assertThat(r.items()).anyMatch(i -> i.type().equals("IPV4") && i.value().equals("203.0.113.5"));
        assertThat(r.items()).anyMatch(i -> i.type().equals("URL") && i.value().startsWith("http://kotu-site.com"));
    }

    @Test
    void ozelVeGenelIpDogruSiniflandirilir() {
        String content = "İç ağ: 10.0.0.5 ve 192.168.1.1 — Dış: 8.8.8.8";
        IocExtractResponse r = service.extract(new IocExtractRequest(content));

        assertThat(r.items()).anyMatch(i -> i.value().equals("10.0.0.5") && i.note().contains("özel/dahili"));
        assertThat(r.items()).anyMatch(i -> i.value().equals("192.168.1.1") && i.note().contains("özel/dahili"));
        assertThat(r.items()).anyMatch(i -> i.value().equals("8.8.8.8") && i.note().contains("genel"));
    }

    @Test
    void hashTurleriDogruAyirtEdilir() {
        String md5 = "d".repeat(32);
        String sha1 = "e".repeat(40);
        String sha256 = "f".repeat(64);
        String content = "MD5: " + md5 + " SHA1: " + sha1 + " SHA256: " + sha256;

        IocExtractResponse r = service.extract(new IocExtractRequest(content));

        assertThat(r.items()).anyMatch(i -> i.type().equals("MD5") && i.value().equals(md5));
        assertThat(r.items()).anyMatch(i -> i.type().equals("SHA1") && i.value().equals(sha1));
        assertThat(r.items()).anyMatch(i -> i.type().equals("SHA256") && i.value().equals(sha256));
    }

    @Test
    void emailIcindekiDomainAyricaTekrarCikarilmaz() {
        String content = "İletişim: saldirgan@kotu-site.com";
        IocExtractResponse r = service.extract(new IocExtractRequest(content));

        long domainCount = r.items().stream().filter(i -> i.type().equals("DOMAIN")).count();
        assertThat(domainCount).isZero();
        assertThat(r.items()).anyMatch(i -> i.type().equals("EMAIL") && i.value().equals("saldirgan@kotu-site.com"));
    }

    @Test
    void standaloneDomainAyriCikarilir() {
        IocExtractResponse r = service.extract(new IocExtractRequest("Ziyaret edilen alan adı: kotu-site.org idi."));

        assertThat(r.items()).anyMatch(i -> i.type().equals("DOMAIN") && i.value().equals("kotu-site.org"));
    }

    @Test
    void bosGirdiBulguUretmezAmaCokmezDe() {
        IocExtractResponse r = service.extract(new IocExtractRequest(""));

        assertThat(r.items()).isEmpty();
        assertThat(r.findings()).anyMatch(f -> f.severity().equals("LOW"));
    }

    @Test
    void aynıGosterge_TekrarEtmezDedupe() {
        IocExtractResponse r = service.extract(new IocExtractRequest("8.8.8.8 ve tekrar 8.8.8.8"));

        long count = r.items().stream().filter(i -> i.value().equals("8.8.8.8")).count();
        assertThat(count).isEqualTo(1);
    }
}
