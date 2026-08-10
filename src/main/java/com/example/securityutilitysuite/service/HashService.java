package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.Finding;
import com.example.securityutilitysuite.dto.HashRequest;
import com.example.securityutilitysuite.dto.HashResponse;
import com.example.securityutilitysuite.util.Codecs;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Ozet (hash) hesaplama, dogrulama ve sozluk saldirisi.
 *
 * Tasarim notlari:
 * - Saf islem: ag, veritabani ve durum yok; sonuclar deterministik.
 * - HASH isleminde TUM algoritmalar birden hesaplanir. Bir ozetin hangi
 *   algoritmadan geldigi cogu zaman bilinmez; hepsini gormek karsilastirmayi
 *   kolaylastirir.
 * - Sozluk KUCUK ve gomulu tutuldu. Amac gercek bir kirma araci olmak degil,
 *   "tuzsuz hizli ozet + zayif parola" birlesiminin ne kadar savunmasiz
 *   oldugunu somut gostermek. Gercek saldirilar milyarlarca kelimelik
 *   listelerle ve GPU ile yapilir.
 * - Karsilastirmalar {@link MessageDigest#isEqual} ile yapilir: erken cikan
 *   string karsilastirmasi zamanlama sizintisina yol acabilir.
 */
@Service
public class HashService {

    /** Desteklenen algoritmalar; zayif olanlar bilerek dahil, uyariyla isaretleniyor. */
    private static final List<String> ALGORITMALAR = List.of("MD5", "SHA-1", "SHA-256", "SHA-512");

    /** Kirilmis veya zayif sayilan algoritmalar. */
    private static final List<String> ZAYIF = List.of("MD5", "SHA-1");

    /** Ozet uzunlugu (hex karakter) -> olasi algoritmalar. */
    private static final Map<Integer, List<String>> UZUNLUK_HARITASI = Map.of(
            32, List.of("MD5", "NTLM", "MD4"),
            40, List.of("SHA-1"),
            56, List.of("SHA-224"),
            64, List.of("SHA-256", "SHA3-256", "BLAKE2s"),
            96, List.of("SHA-384"),
            128, List.of("SHA-512", "SHA3-512", "BLAKE2b")
    );

    /**
     * Gomulu sozluk. Gercek sizinti listelerinde en sik gorulen parolalardan
     * secildi; kisa tutuldu cunku amac gosterim, kapsamli kirma degil.
     */
    private static final List<String> SOZLUK = List.of(
            "123456", "password", "12345678", "qwerty", "123456789", "12345",
            "1234", "111111", "1234567", "dragon", "123123", "baseball",
            "abc123", "football", "monkey", "letmein", "shadow", "master",
            "666666", "qwertyuiop", "123321", "mustang", "1234567890",
            "michael", "654321", "superman", "1qaz2wsx", "7777777", "121212",
            "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan",
            "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer",
            "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou",
            "charlie", "robert", "thomas", "hockey", "ranger", "daniel",
            "starwars", "klaster", "112233", "george", "computer", "michelle",
            "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111",
            "131313", "freedom", "777777", "pass", "maggie", "159753",
            "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda",
            "summer", "love", "ashley", "nicole", "chelsea", "biteme",
            "matthew", "access", "yankees", "987654321", "dallas", "austin",
            "thunder", "taylor", "matrix", "admin", "administrator", "root",
            "toor", "guest", "test", "user", "welcome", "login", "passw0rd",
            "sifre", "parola", "sifre123", "deneme", "merhaba", "galatasaray",
            "fenerbahce", "besiktas", "turkiye", "istanbul", "ankara",
            "Sifre123456", "Test1234!", "P@ssw0rd", "Passw0rd!", "qwerty123"
    );

    // ------------------------------------------------------------------

    public HashResponse process(HashRequest request) {
        return switch (request.getOperation()) {
            case HASH -> hesapla(request);
            case VERIFY -> dogrula(request);
            case CRACK -> kir(request);
        };
    }

    // ------------------------------------------------------------------
    // HASH
    // ------------------------------------------------------------------

    private HashResponse hesapla(HashRequest request) {
        String input = request.getInput();
        if (input == null || input.isEmpty()) {
            throw new IllegalArgumentException("Özetlenecek metin boş olamaz");
        }

        Map<String, String> digests = new LinkedHashMap<>();
        for (String alg : ALGORITMALAR) {
            digests.put(alg, ozet(alg, input));
        }

        List<Finding> f = new ArrayList<>();
        f.add(Finding.medium("MD5 ve SHA-1 kırılmıştır; çakışma üretilebildiği için "
                + "imza ve parola saklamada kullanılmamalıdır."));
        f.add(Finding.high("Parola saklamak için düz özet (SHA-256 dahil) UYGUN DEĞİLDİR. "
                + "Hızlı hesaplandıkları için saniyede milyarlarca deneme yapılabilir. "
                + "bcrypt, scrypt veya Argon2 kullanın."));

        return new HashResponse("HASH", digests, List.of(), null, null, null, 0, f);
    }

    // ------------------------------------------------------------------
    // VERIFY
    // ------------------------------------------------------------------

    private HashResponse dogrula(HashRequest request) {
        String input = request.getInput();
        String hedef = normalize(request.getHash());

        if (input == null || input.isEmpty()) {
            throw new IllegalArgumentException("Karşılaştırılacak metin boş olamaz");
        }
        if (hedef.isEmpty()) {
            throw new IllegalArgumentException("Karşılaştırılacak hash değeri boş olamaz");
        }

        Map<String, String> digests = new LinkedHashMap<>();
        String eslesenAlg = null;

        for (String alg : ALGORITMALAR) {
            String hesaplanan = ozet(alg, input);
            digests.put(alg, hesaplanan);
            // Sabit zamanli karsilastirma: erken cikan == karsilastirmasi
            // teorik olarak zamanlama bilgisi sizdirabilir.
            if (MessageDigest.isEqual(hesaplanan.getBytes(StandardCharsets.UTF_8),
                                      hedef.getBytes(StandardCharsets.UTF_8))) {
                eslesenAlg = alg;
            }
        }

        List<Finding> f = new ArrayList<>();
        if (eslesenAlg != null && ZAYIF.contains(eslesenAlg)) {
            f.add(Finding.high("Eşleşme zayıf bir algoritmayla sağlandı: " + eslesenAlg
                    + ". Bu algoritma kırılmıştır."));
        }
        if (eslesenAlg == null) {
            f.add(Finding.low("Hiçbir algoritmada eşleşme bulunamadı. Hash farklı bir "
                    + "algoritmadan, tuzlu (salted) veya farklı kodlamada olabilir."));
        }

        return new HashResponse("VERIFY", digests, tanimla(hedef),
                eslesenAlg != null, eslesenAlg, null, 0, f);
    }

    // ------------------------------------------------------------------
    // CRACK
    // ------------------------------------------------------------------

    private HashResponse kir(HashRequest request) {
        String hedef = normalize(request.getHash());
        if (hedef.isEmpty()) {
            throw new IllegalArgumentException("Kırılacak hash değeri boş olamaz");
        }

        List<String> olasiAlgoritmalar = tanimla(hedef);
        // Uzunluktan tanimlanamadiysa hepsini dene.
        List<String> denenecek = olasiAlgoritmalar.stream()
                .filter(ALGORITMALAR::contains)
                .toList();
        if (denenecek.isEmpty()) {
            denenecek = ALGORITMALAR;
        }

        String bulunan = null;
        String bulunanAlg = null;
        int denenen = 0;

        dis:
        for (String kelime : SOZLUK) {
            denenen++;
            for (String alg : denenecek) {
                if (MessageDigest.isEqual(ozet(alg, kelime).getBytes(StandardCharsets.UTF_8),
                                          hedef.getBytes(StandardCharsets.UTF_8))) {
                    bulunan = kelime;
                    bulunanAlg = alg;
                    break dis;
                }
            }
        }

        List<Finding> f = new ArrayList<>();
        if (bulunan != null) {
            f.add(Finding.critical("Parola " + denenen + " denemede kırıldı. "
                    + "Bu, yaygın parola listesinde bulunan zayıf bir paroladır."));
            if (ZAYIF.contains(bulunanAlg)) {
                f.add(Finding.high("Üstelik zayıf bir algoritma kullanılmış: " + bulunanAlg));
            }
        } else {
            f.add(Finding.low("Gömülü sözlükte (" + SOZLUK.size() + " kelime) eşleşme yok. "
                    + "Bu, parolanın güçlü olduğu ANLAMINA GELMEZ — gerçek saldırılar "
                    + "milyarlarca kelimelik listelerle ve GPU ile yapılır."));
        }

        return new HashResponse("CRACK", Map.of(), olasiAlgoritmalar,
                bulunan != null, bulunanAlg, bulunan, denenen, f);
    }

    // ------------------------------------------------------------------
    // Yardimcilar
    // ------------------------------------------------------------------

    private String ozet(String algoritma, String metin) {
        try {
            MessageDigest md = MessageDigest.getInstance(algoritma);
            return Codecs.hexEncode(md.digest(metin.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Algoritma bulunamadı: " + algoritma, ex);
        }
    }

    /** Ozet uzunluguna gore olasi algoritmalari listeler. */
    private List<String> tanimla(String hash) {
        return UZUNLUK_HARITASI.getOrDefault(hash.length(), List.of());
    }

    /** Bosluk ve buyuk/kucuk harf farkini giderir. */
    private String normalize(String hash) {
        return hash == null ? "" : hash.replaceAll("\\s", "").toLowerCase();
    }
}
