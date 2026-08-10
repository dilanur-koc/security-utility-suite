package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.CryptoRequest;
import com.example.securityutilitysuite.dto.CryptoResponse;
import com.example.securityutilitysuite.dto.Finding;
import com.example.securityutilitysuite.util.Codecs;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * AES-256-GCM sifreleme ve egitim amacli Sezar kaydirmasi.
 *
 * AES TASARIM KARARLARI:
 * - GCM modu secildi (CBC veya ECB degil). GCM kimlik dogrulamali sifreleme
 *   saglar: veri degistirilirse cozme BASARISIZ olur. CBC'de bu koruma yoktur
 *   ve dolgu oracle saldirilarina acik olabilir; ECB ise ayni duz metin
 *   bloklarini ayni sifreli bloklara cevirdigi icin desen sizdirir.
 * - Anahtar paroladan PBKDF2 ile turetilir, 210.000 iterasyonla (OWASP'in
 *   PBKDF2-HMAC-SHA256 icin onerdigi deger). Parolayi dogrudan anahtar
 *   olarak kullanmak kaba kuvveti ucuzlatirdi.
 * - Her sifrelemede RASTGELE tuz ve IV uretilir. Ayni parolayla ayni metin
 *   her seferinde farkli cikti verir; sabit IV kullanmak GCM'de anahtarin
 *   tamamen cozulmesine yol acar.
 * - Cikti bicimi: salt(16) || iv(12) || ciphertext+tag, Base64 kodlu.
 *   Cozme icin gereken her sey ciktinin icinde; tuz ve IV gizli degildir.
 *
 * SEZAR: sifreleme DEGILDIR, yalnizca yer degistirmedir. Modulde bilerek
 * bulunuyor cunku "sifreleme gibi gorunen ama koruma saglamayan" seylerin
 * ne demek oldugunu gostermek egitici. Her kullanimda uyari uretir.
 */
@Service
public class CryptoService {

    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;          // GCM icin onerilen
    private static final int TAG_LENGTH_BITS = 128;
    private static final int KEY_LENGTH_BITS = 256;
    private static final int PBKDF2_ITERATIONS = 210_000;

    private static final int MIN_PASSWORD_LENGTH = 12;

    private final SecureRandom random = new SecureRandom();

    public CryptoResponse process(CryptoRequest request) {
        return switch (request.getAlgorithm()) {
            case AES_GCM -> aes(request);
            case CAESAR -> caesar(request);
        };
    }

    // ------------------------------------------------------------------
    // AES-256-GCM
    // ------------------------------------------------------------------

    private CryptoResponse aes(CryptoRequest request) {
        String parola = request.getPassword();
        if (parola == null || parola.isEmpty()) {
            throw new IllegalArgumentException("AES için parola gerekli");
        }

        List<CryptoResponse.Detail> details = new ArrayList<>();
        List<Finding> findings = new ArrayList<>();
        parolaBulgulari(parola, findings);

        try {
            if (request.getOperation() == CryptoRequest.Operation.ENCRYPT) {
                byte[] salt = new byte[SALT_LENGTH];
                byte[] iv = new byte[IV_LENGTH];
                random.nextBytes(salt);
                random.nextBytes(iv);

                SecretKey key = anahtarTuret(parola, salt);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
                byte[] sifreli = cipher.doFinal(request.getInput().getBytes(StandardCharsets.UTF_8));

                // salt || iv || ciphertext+tag
                byte[] paket = ByteBuffer.allocate(salt.length + iv.length + sifreli.length)
                        .put(salt).put(iv).put(sifreli).array();
                String output = Codecs.base64Encode(paket);

                details.add(new CryptoResponse.Detail("Mod", "AES-256-GCM (kimlik doğrulamalı)"));
                details.add(new CryptoResponse.Detail("Anahtar türetme",
                        "PBKDF2-HMAC-SHA256, " + String.format("%,d", PBKDF2_ITERATIONS) + " iterasyon"));
                details.add(new CryptoResponse.Detail("Tuz (salt)", Codecs.hexEncode(salt)));
                details.add(new CryptoResponse.Detail("IV (nonce)", Codecs.hexEncode(iv)));
                details.add(new CryptoResponse.Detail("Doğrulama etiketi", TAG_LENGTH_BITS + " bit"));
                details.add(new CryptoResponse.Detail("Çıktı biçimi", "Base64(salt‖iv‖şifreli+etiket)"));

                findings.add(Finding.low("Her şifrelemede rastgele tuz ve IV üretilir; "
                        + "aynı metin aynı parolayla farklı çıktı verir. Bu beklenen davranıştır."));

                return new CryptoResponse(output, "AES_GCM", "ENCRYPT",
                        KEY_LENGTH_BITS, output.length(), details, findings);
            }

            // --- DECRYPT ---
            byte[] paket = Codecs.base64Decode(request.getInput());
            if (paket.length < SALT_LENGTH + IV_LENGTH + 16) {
                throw new IllegalArgumentException(
                        "Şifreli veri çok kısa veya bozuk (en az " + (SALT_LENGTH + IV_LENGTH + 16)
                        + " bayt bekleniyor, " + paket.length + " geldi)");
            }

            ByteBuffer bb = ByteBuffer.wrap(paket);
            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[IV_LENGTH];
            bb.get(salt);
            bb.get(iv);
            byte[] sifreli = new byte[bb.remaining()];
            bb.get(sifreli);

            SecretKey key = anahtarTuret(parola, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));

            byte[] cozulen;
            try {
                cozulen = cipher.doFinal(sifreli);
            } catch (Exception ex) {
                // GCM'de bu iki durum ayirt EDILEMEZ ve edilmemeli:
                // yanlis parola mi, veri mi degistirilmis — ayni hatayi verir.
                throw new IllegalArgumentException(
                        "Çözme başarısız: parola yanlış veya veri değiştirilmiş. "
                        + "GCM bütünlüğü de doğruladığı için bu ikisi ayırt edilemez.");
            }

            String output = new String(cozulen, StandardCharsets.UTF_8);
            details.add(new CryptoResponse.Detail("Mod", "AES-256-GCM"));
            details.add(new CryptoResponse.Detail("Tuz (salt)", Codecs.hexEncode(salt)));
            details.add(new CryptoResponse.Detail("IV (nonce)", Codecs.hexEncode(iv)));
            details.add(new CryptoResponse.Detail("Bütünlük", "Doğrulandı (GCM etiketi geçerli)"));

            return new CryptoResponse(output, "AES_GCM", "DECRYPT",
                    KEY_LENGTH_BITS, output.length(), details, findings);

        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalStateException("Şifreleme işlemi başarısız: " + ex.getMessage(), ex);
        }
    }

    private SecretKey anahtarTuret(String parola, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(parola.toCharArray(), salt,
                PBKDF2_ITERATIONS, KEY_LENGTH_BITS);
        try {
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        } finally {
            spec.clearPassword();   // parolayi bellekte birakma
        }
    }

    private void parolaBulgulari(String parola, List<Finding> f) {
        if (parola.length() < MIN_PASSWORD_LENGTH) {
            f.add(Finding.high("Parola " + parola.length() + " karakter. "
                    + "AES anahtarı bu paroladan türetildiği için güvenlik doğrudan "
                    + "parolanın gücüne bağlı; en az " + MIN_PASSWORD_LENGTH
                    + " karakter kullanın."));
        }
        if (parola.matches("^[a-z]+$") || parola.matches("^[0-9]+$")) {
            f.add(Finding.high("Parola yalnızca tek tür karakter içeriyor; "
                    + "kaba kuvvete karşı çok zayıf."));
        }
    }

    // ------------------------------------------------------------------
    // Sezar
    // ------------------------------------------------------------------

    private CryptoResponse caesar(CryptoRequest request) {
        int kaydirma = request.getOperation() == CryptoRequest.Operation.ENCRYPT
                ? request.getShift()
                : -request.getShift();

        String output = kaydir(request.getInput(), kaydirma);

        List<CryptoResponse.Detail> details = List.of(
                new CryptoResponse.Detail("Kaydırma", String.valueOf(request.getShift())),
                new CryptoResponse.Detail("Kapsam", "Yalnızca A-Z ve a-z; diğer karakterler korunur"),
                new CryptoResponse.Detail("Olası anahtar sayısı", "25")
        );

        List<Finding> findings = List.of(
                Finding.critical("Sezar şifresi ŞİFRELEME DEĞİLDİR. Yalnızca 25 olası anahtar "
                        + "vardır; hepsi saniyeler içinde denenebilir. Frekans analiziyle "
                        + "anahtar bilinmeden de çözülür. Gerçek veri korumak için ASLA "
                        + "kullanmayın — bu modül yalnızca eğitim amaçlıdır."),
                Finding.low("Karşılaştırma için aynı metni AES-256-GCM ile şifreleyip "
                        + "farkı görebilirsiniz.")
        );

        return new CryptoResponse(output, "CAESAR", request.getOperation().name(),
                0, output.length(), details, findings);
    }

    /** Yalnizca ASCII harfleri kaydirir; Turkce karakterler ve isaretler korunur. */
    private String kaydir(String metin, int kaydirma) {
        int k = ((kaydirma % 26) + 26) % 26;   // negatif kaydirmayi normalize et
        StringBuilder sb = new StringBuilder(metin.length());

        for (char c : metin.toCharArray()) {
            if (c >= 'a' && c <= 'z') {
                sb.append((char) ('a' + (c - 'a' + k) % 26));
            } else if (c >= 'A' && c <= 'Z') {
                sb.append((char) ('A' + (c - 'A' + k) % 26));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
