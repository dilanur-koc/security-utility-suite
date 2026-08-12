package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.CryptoRequest;
import com.example.securityutilitysuite.dto.CryptoResponse;
import com.example.securityutilitysuite.dto.Finding;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static com.example.securityutilitysuite.dto.CryptoRequest.Algorithm.AES_GCM;
import static com.example.securityutilitysuite.dto.CryptoRequest.Algorithm.CAESAR;
import static com.example.securityutilitysuite.dto.CryptoRequest.Operation.DECRYPT;
import static com.example.securityutilitysuite.dto.CryptoRequest.Operation.ENCRYPT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link CryptoService} icin birim testleri.
 *
 * AES ciktisi her calistirmada FARKLI olur (rastgele tuz ve IV), bu yuzden
 * sabit bir beklenen deger yazilamaz. Bunun yerine dogrulanan seyler:
 * gidis-donus tutarliligi, yanlis parolanin reddi, ve en onemlisi
 * DEGISTIRILMIS VERININ reddi — GCM'in kimlik dogrulama ozelligi.
 *
 * Not: PBKDF2 210.000 iterasyon kullandigi icin her AES islemi ~0.5 sn
 * suruyor. Test sayisi bu yuzden bilerek sinirli tutuldu.
 */
@DisplayName("CryptoService — AES-256-GCM ve Sezar")
class CryptoServiceTest {

    private static final String PAROLA = "CokGucluParola2026!";

    private CryptoService service;

    @BeforeEach
    void setUp() {
        service = new CryptoService();
    }

    private String sifrele(String metin, String parola) {
        return service.process(new CryptoRequest(metin, parola, 0, AES_GCM, ENCRYPT)).output();
    }

    private CryptoResponse coz(String sifreli, String parola) {
        return service.process(new CryptoRequest(sifreli, parola, 0, AES_GCM, DECRYPT));
    }

    // ==================================================================

    @Nested
    @DisplayName("AES-256-GCM")
    class Aes {

        @Test
        @DisplayName("Şifrelenen metin aynı parolayla geri çözülür")
        void gidisDonus() {
            String metin = "Gizli mesaj: şğüöçİ 123";
            assertThat(coz(sifrele(metin, PAROLA), PAROLA).output()).isEqualTo(metin);
        }

        @Test
        @DisplayName("Aynı metin her şifrelemede farklı çıktı verir")
        void rastgeleTuzVeIv() {
            // Sabit IV kullanilsaydi ciktilar ayni olurdu — GCM'de bu
            // anahtarin tamamen cozulmesine yol acar.
            String a = sifrele("aynı metin", PAROLA);
            String b = sifrele("aynı metin", PAROLA);

            assertThat(a).isNotEqualTo(b);
            assertThat(coz(a, PAROLA).output()).isEqualTo(coz(b, PAROLA).output());
        }

        @Test
        @DisplayName("Yanlış parola çözemez")
        void yanlisParola() {
            String sifreli = sifrele("gizli", PAROLA);

            assertThatThrownBy(() -> coz(sifreli, "BaskaParola2026!"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("parola yanlış veya veri değiştirilmiş");
        }

        @Test
        @DisplayName("Değiştirilmiş veri reddedilir (GCM bütünlük koruması)")
        void veriDegistirilmis() {
            String sifreli = sifrele("gizli mesaj", PAROLA);

            // BAYT seviyesinde degistiriyoruz, karakter seviyesinde degil.
            // Base64'te son karakterin bazi bitleri kullanilmaz; karakteri
            // degistirmek cozulen baytlari HER ZAMAN degistirmez (olculdu:
            // 100 denemenin 9'unda bayt ayni kaliyor). O durumda GCM hakli
            // olarak "bozulma yok" der ve test rastgele basarisiz olurdu.
            byte[] ham = Base64.getDecoder().decode(sifreli);
            ham[ham.length - 1] ^= 0x01;   // dogrulama etiketinin son bitini cevir
            String bozuk = Base64.getEncoder().encodeToString(ham);

            assertThatThrownBy(() -> coz(bozuk, PAROLA))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("parola yanlış veya veri değiştirilmiş");
        }

        @Test
        @DisplayName("Parola zorunlu")
        void parolaZorunlu() {
            assertThatThrownBy(() -> sifrele("metin", ""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("parola gerekli");
        }

        @Test
        @DisplayName("Kısa parola uyarı üretir")
        void kisaParolaUyarisi() {
            CryptoResponse r = service.process(
                    new CryptoRequest("metin", "kisa123", 0, AES_GCM, ENCRYPT));

            assertThat(r.findings()).extracting(Finding::severity).contains("HIGH");
        }

        @Test
        @DisplayName("Anahtar uzunluğu 256 bit bildirilir")
        void anahtarUzunlugu() {
            CryptoResponse r = service.process(
                    new CryptoRequest("metin", PAROLA, 0, AES_GCM, ENCRYPT));

            assertThat(r.keyBits()).isEqualTo(256);
            assertThat(r.details()).extracting(CryptoResponse.Detail::value)
                    .anyMatch(v -> v.contains("GCM"));
        }

        @Test
        @DisplayName("Bozuk Base64 girdisi anlaşılır hata verir")
        void bozukGirdi() {
            assertThatThrownBy(() -> coz("bu-gecerli-sifreli-veri-degil", PAROLA))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    // ==================================================================

    @Nested
    @DisplayName("Sezar şifresi")
    class Sezar {

        private String sezar(String metin, int kaydirma, CryptoRequest.Operation op) {
            return service.process(new CryptoRequest(metin, null, kaydirma, CAESAR, op)).output();
        }

        @Test
        @DisplayName("Bilinen kaydırma sonucu doğru")
        void bilinenDeger() {
            assertThat(sezar("Hello, World!", 3, ENCRYPT)).isEqualTo("Khoor, Zruog!");
        }

        @Test
        @DisplayName("Şifrelenip çözülünce aslına döner")
        void gidisDonus() {
            String metin = "Merhaba Dünya 123!";
            assertThat(sezar(sezar(metin, 7, ENCRYPT), 7, DECRYPT)).isEqualTo(metin);
        }

        @Test
        @DisplayName("Harf dışı karakterler ve Türkçe harfler korunur")
        void korunanKarakterler() {
            // Sadece ASCII harfler kaydirilir; digerleri aynen kalir.
            String sonuc = sezar("abc-123 şğü", 1, ENCRYPT);
            assertThat(sonuc).isEqualTo("bcd-123 şğü");
        }

        @Test
        @DisplayName("26 kaydırma metni değiştirmez")
        void tamTur() {
            assertThat(sezar("abcXYZ", 26, ENCRYPT)).isEqualTo("abcXYZ");
        }

        @Test
        @DisplayName("Şifreleme olmadığı kritik uyarıyla belirtilir")
        void kritikUyari() {
            CryptoResponse r = service.process(
                    new CryptoRequest("metin", null, 3, CAESAR, ENCRYPT));

            assertThat(r.findings()).extracting(Finding::severity).contains("CRITICAL");
            assertThat(r.findings()).extracting(Finding::message)
                    .anyMatch(m -> m.contains("ŞİFRELEME DEĞİLDİR"));
            assertThat(r.keyBits()).isZero();
        }
    }
}
