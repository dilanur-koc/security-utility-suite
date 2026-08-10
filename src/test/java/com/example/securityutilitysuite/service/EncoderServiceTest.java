package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.EncodeRequest;
import com.example.securityutilitysuite.dto.EncodeResponse;
import com.example.securityutilitysuite.dto.Finding;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static com.example.securityutilitysuite.dto.EncodeRequest.Format.BASE64;
import static com.example.securityutilitysuite.dto.EncodeRequest.Format.BASE64URL;
import static com.example.securityutilitysuite.dto.EncodeRequest.Format.HEX;
import static com.example.securityutilitysuite.dto.EncodeRequest.Operation.DECODE;
import static com.example.securityutilitysuite.dto.EncodeRequest.Operation.ENCODE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link EncoderService} icin birim testleri.
 *
 * Servis saf islem yaptigi icin — ag, veritabani veya zaman bagimliligi yok —
 * sonuclar tamamen deterministik. Bu yuzden sinir durumlari (Turkce karakter,
 * ikili veri, bozuk girdi, gidis-donus tutarliligi) eksiksiz sinanabiliyor.
 */
@DisplayName("EncoderService — Base64 / Base64URL / Hex dönüşümü")
class EncoderServiceTest {

    private EncoderService service;

    @BeforeEach
    void setUp() {
        service = new EncoderService();
    }

    private EncodeResponse calistir(String girdi, EncodeRequest.Format f, EncodeRequest.Operation o) {
        return service.convert(new EncodeRequest(girdi, f, o));
    }

    // ==================================================================
    // Kodlama
    // ==================================================================

    @Nested
    @DisplayName("Kodlama")
    class Kodlama {

        @Test
        @DisplayName("Base64 kodlaması bilinen değerle eşleşir")
        void base64() {
            assertThat(calistir("Hello", BASE64, ENCODE).output()).isEqualTo("SGVsbG8=");
        }

        @Test
        @DisplayName("Base64URL dolgusuz ve URL-güvenli karakterlerle üretilir")
        void base64Url() {
            // Standart Base64'te + ve / cikan bir girdi seciyoruz.
            String girdi = "~~~??>>";
            String std = calistir(girdi, BASE64, ENCODE).output();
            String url = calistir(girdi, BASE64URL, ENCODE).output();

            assertThat(url).doesNotContain("+", "/", "=");
            assertThat(std).isNotEqualTo(url);
        }

        @Test
        @DisplayName("Hex kodlaması küçük harfle üretilir")
        void hex() {
            assertThat(calistir("Hello", HEX, ENCODE).output()).isEqualTo("48656c6c6f");
        }

        @Test
        @DisplayName("Türkçe karakterler UTF-8 olarak kodlanır")
        void turkceKarakter() {
            EncodeResponse r = calistir("şğüöçİ", HEX, ENCODE);
            // Her Turkce karakter UTF-8'de 2 bayt: 6 karakter -> 12 bayt
            assertThat(r.byteLength()).isEqualTo(12);
            assertThat(r.output()).hasSize(24);
        }
    }

    // ==================================================================
    // Cozme
    // ==================================================================

    @Nested
    @DisplayName("Çözme")
    class Cozme {

        @Test
        @DisplayName("Base64 çözülür")
        void base64() {
            assertThat(calistir("SGVsbG8=", BASE64, DECODE).output()).isEqualTo("Hello");
        }

        @Test
        @DisplayName("Dolgusuz Base64URL çözülür (JWT parçaları böyle gelir)")
        void dolgusuzBase64Url() {
            // Gercek bir JWT header'i — sonunda "=" yok
            String header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
            assertThat(calistir(header, BASE64URL, DECODE).output())
                    .isEqualTo("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        }

        @Test
        @DisplayName("Hex farklı ayraçlarla çözülür")
        void hexAyraclar() {
            for (String bicim : new String[]{"48656c6c6f", "48 65 6c 6c 6f",
                                             "48:65:6c:6c:6f", "0x48656c6c6f"}) {
                assertThat(calistir(bicim, HEX, DECODE).output())
                        .as("biçim: %s", bicim)
                        .isEqualTo("Hello");
            }
        }

        @Test
        @DisplayName("Metin olmayan veri hex olarak gösterilir, asText null kalır")
        void ikiliVeri() {
            // 0xFF 0xFE gecerli UTF-8 degil
            EncodeResponse r = calistir("fffe", HEX, DECODE);

            assertThat(r.asText()).isNull();
            assertThat(r.output()).isEqualTo("fffe");
            assertThat(r.findings()).extracting(Finding::message)
                    .anyMatch(m -> m.contains("UTF-8"));
        }
    }

    // ==================================================================
    // Gidis-donus
    // ==================================================================

    @Nested
    @DisplayName("Gidiş-dönüş tutarlılığı")
    class GidisDonus {

        @Test
        @DisplayName("Kodlanan değer çözülünce aslına döner")
        void tumBicimler() {
            String[] girdiler = {"Hello", "şğüöçİ", "a", "{\"k\":\"v\"}",
                                 "çok uzun bir metin ".repeat(50)};

            for (String girdi : girdiler) {
                for (EncodeRequest.Format f : EncodeRequest.Format.values()) {
                    String kodlu = calistir(girdi, f, ENCODE).output();
                    assertThat(calistir(kodlu, f, DECODE).output())
                            .as("biçim %s, girdi uzunluğu %d", f, girdi.length())
                            .isEqualTo(girdi);
                }
            }
        }

        @Test
        @DisplayName("Tüm gösterimler aynı veriyi tarif eder")
        void tumGosterimler() {
            EncodeResponse r = calistir("Hello", BASE64, ENCODE);

            assertThat(r.asText()).isEqualTo("Hello");
            assertThat(r.asBase64()).isEqualTo("SGVsbG8=");
            assertThat(r.asHex()).isEqualTo("48656c6c6f");
            assertThat(r.asBase64Url()).doesNotContain("=");
            assertThat(r.byteLength()).isEqualTo(5);
        }
    }

    // ==================================================================
    // Bulgular
    // ==================================================================

    @Nested
    @DisplayName("Güvenlik bulguları")
    class Bulgular {

        @Test
        @DisplayName("Çözülen içerikte parola geçerse uyarı verilir")
        void hassasVeri() {
            String kodlu = calistir("{\"password\":\"gizli123\"}", BASE64, ENCODE).output();
            EncodeResponse r = calistir(kodlu, BASE64, DECODE);

            assertThat(r.findings()).extracting(Finding::severity).contains("HIGH");
            assertThat(r.findings()).extracting(Finding::message)
                    .anyMatch(m -> m.contains("şifreleme DEĞİLDİR"));
        }

        @Test
        @DisplayName("Çözülen değer JWT yapısındaysa işaretlenir")
        void jwtTespiti() {
            String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123";
            String kodlu = calistir(jwt, BASE64, ENCODE).output();

            assertThat(calistir(kodlu, BASE64, DECODE).findings())
                    .extracting(Finding::message)
                    .anyMatch(m -> m.contains("JWT"));
        }

        @Test
        @DisplayName("Sıradan metinde gereksiz uyarı üretilmez")
        void yanlisPozitifYok() {
            String kodlu = calistir("merhaba dünya", BASE64, ENCODE).output();
            assertThat(calistir(kodlu, BASE64, DECODE).findings()).isEmpty();
        }
    }

    // ==================================================================
    // Gecersiz girdi
    // ==================================================================

    @Nested
    @DisplayName("Geçersiz girdiler")
    class Gecersiz {

        @Test
        @DisplayName("Bozuk Base64 reddedilir")
        void bozukBase64() {
            assertThatThrownBy(() -> calistir("!!!not-base64!!!", BASE64, DECODE))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Base64");
        }

        @Test
        @DisplayName("Tek uzunlukta hex reddedilir")
        void tekUzunlukHex() {
            assertThatThrownBy(() -> calistir("48656", HEX, DECODE))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("çift olmalı");
        }

        @Test
        @DisplayName("Hex dışı karakter reddedilir")
        void hexDisiKarakter() {
            assertThatThrownBy(() -> calistir("zzzz", HEX, DECODE))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }
}
