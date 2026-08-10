package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.Finding;
import com.example.securityutilitysuite.dto.HashRequest;
import com.example.securityutilitysuite.dto.HashResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static com.example.securityutilitysuite.dto.HashRequest.Operation.CRACK;
import static com.example.securityutilitysuite.dto.HashRequest.Operation.HASH;
import static com.example.securityutilitysuite.dto.HashRequest.Operation.VERIFY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link HashService} icin birim testleri.
 *
 * Ozet degerleri evrensel sabitler oldugu icin beklentiler bilinen
 * degerlere karsi yazildi (orn. MD5("123456")). Bu, testin gercekten
 * dogru hesaplandigini kanitlar — kendi ciktisini kendine dogrulatmaz.
 */
@DisplayName("HashService — özet hesaplama, doğrulama ve kırma")
class HashServiceTest {

    private HashService service;

    @BeforeEach
    void setUp() {
        service = new HashService();
    }

    private HashResponse hash(String input) {
        return service.process(new HashRequest(input, null, HASH));
    }

    // ==================================================================

    @Nested
    @DisplayName("Özet hesaplama")
    class Hesaplama {

        @Test
        @DisplayName("Bilinen değerlerle eşleşir")
        void bilinenDegerler() {
            HashResponse r = hash("123456");

            assertThat(r.digests().get("MD5")).isEqualTo("e10adc3949ba59abbe56e057f20f883e");
            assertThat(r.digests().get("SHA-256"))
                    .isEqualTo("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92");
        }

        @Test
        @DisplayName("Tüm algoritmalar doğru uzunlukta üretilir")
        void uzunluklar() {
            HashResponse r = hash("test");

            assertThat(r.digests().get("MD5")).hasSize(32);
            assertThat(r.digests().get("SHA-1")).hasSize(40);
            assertThat(r.digests().get("SHA-256")).hasSize(64);
            assertThat(r.digests().get("SHA-512")).hasSize(128);
        }

        @Test
        @DisplayName("Aynı girdi aynı özeti, farklı girdi farklı özeti verir")
        void deterministik() {
            assertThat(hash("abc").digests()).isEqualTo(hash("abc").digests());
            assertThat(hash("abc").digests().get("SHA-256"))
                    .isNotEqualTo(hash("abd").digests().get("SHA-256"));
        }

        @Test
        @DisplayName("Parola saklama uyarısı her zaman verilir")
        void parolaUyarisi() {
            assertThat(hash("x").findings()).extracting(Finding::message)
                    .anyMatch(m -> m.contains("bcrypt"));
        }

        @Test
        @DisplayName("Boş girdi reddedilir")
        void bosGirdi() {
            assertThatThrownBy(() -> hash(""))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    // ==================================================================

    @Nested
    @DisplayName("Doğrulama")
    class Dogrulama {

        @Test
        @DisplayName("Doğru hash eşleşir ve algoritma bildirilir")
        void eslesme() {
            HashResponse r = service.process(new HashRequest(
                    "123456", "e10adc3949ba59abbe56e057f20f883e", VERIFY));

            assertThat(r.matched()).isTrue();
            assertThat(r.matchedAlgorithm()).isEqualTo("MD5");
        }

        @Test
        @DisplayName("Büyük harfli ve boşluklu hash de kabul edilir")
        void normalizasyon() {
            HashResponse r = service.process(new HashRequest(
                    "123456", " E10ADC3949BA59ABBE56E057F20F883E ", VERIFY));

            assertThat(r.matched()).isTrue();
        }

        @Test
        @DisplayName("Yanlış hash eşleşmez")
        void eslesmeYok() {
            HashResponse r = service.process(new HashRequest(
                    "123456", "0".repeat(32), VERIFY));

            assertThat(r.matched()).isFalse();
            assertThat(r.matchedAlgorithm()).isNull();
        }

        @Test
        @DisplayName("Zayıf algoritmayla eşleşme uyarı üretir")
        void zayifAlgoritmaUyarisi() {
            HashResponse r = service.process(new HashRequest(
                    "123456", "e10adc3949ba59abbe56e057f20f883e", VERIFY));

            assertThat(r.findings()).extracting(Finding::message)
                    .anyMatch(m -> m.contains("MD5"));
        }

        @Test
        @DisplayName("Hash uzunluğundan algoritma tahmin edilir")
        void algoritmaTahmini() {
            HashResponse r = service.process(new HashRequest(
                    "x", "e10adc3949ba59abbe56e057f20f883e", VERIFY));

            assertThat(r.identifiedTypes()).contains("MD5");
        }
    }

    // ==================================================================

    @Nested
    @DisplayName("Sözlük saldırısı")
    class Kirma {

        @Test
        @DisplayName("Sözlükteki zayıf parola kırılır")
        void zayifParolaKirilir() {
            // MD5("123456")
            HashResponse r = service.process(new HashRequest(
                    null, "e10adc3949ba59abbe56e057f20f883e", CRACK));

            assertThat(r.cracked()).isEqualTo("123456");
            assertThat(r.matchedAlgorithm()).isEqualTo("MD5");
            assertThat(r.findings()).extracting(Finding::severity).contains("CRITICAL");
        }

        @Test
        @DisplayName("SHA-256 özet de kırılır")
        void sha256Kirilir() {
            // SHA-256("password")
            HashResponse r = service.process(new HashRequest(null,
                    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", CRACK));

            assertThat(r.cracked()).isEqualTo("password");
            assertThat(r.matchedAlgorithm()).isEqualTo("SHA-256");
        }

        @Test
        @DisplayName("Sözlükte olmayan parola kırılamaz ve yanıltıcı mesaj verilmez")
        void guclUParolaKirilmaz() {
            // SHA-256("xK9#mQ2$vL7@nP4z") — sozlukte yok
            HashResponse r = service.process(new HashRequest(null,
                    "0".repeat(64), CRACK));

            assertThat(r.cracked()).isNull();
            assertThat(r.findings()).extracting(Finding::message)
                    .anyMatch(m -> m.contains("ANLAMINA GELMEZ"));
        }

        @Test
        @DisplayName("Boş hash reddedilir")
        void bosHash() {
            assertThatThrownBy(() -> service.process(new HashRequest(null, "", CRACK)))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }
}
