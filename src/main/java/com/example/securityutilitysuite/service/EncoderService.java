package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.EncodeRequest;
import com.example.securityutilitysuite.dto.EncodeResponse;
import com.example.securityutilitysuite.dto.Finding;
import com.example.securityutilitysuite.util.Codecs;
import org.springframework.stereotype.Service;

import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Metin ile Base64 / Base64URL / hex arasinda donusum yapar.
 *
 * Tasarim notlari:
 * - Tamamen saf islem: ag erisimi, veritabani ve durum yok. Sonuclar
 *   deterministik oldugu icin eksiksiz birim testi yazilabiliyor.
 * - Cozme sonucunda veri her zaman metin OLMAYABILIR (sifreli veri, resim,
 *   ikili dosya). Bu durumda {@code asText} null birakilir; bozuk karakter
 *   basmaktansa "metin degil" demek dogru olan.
 * - Bir guvenlik araci oldugu icin yalnizca donusturmuyor, cozulen icerikte
 *   dikkat cekici sey varsa isaretliyor: ic ice kodlama, JWT benzeri yapi,
 *   olasi kimlik bilgisi.
 */
@Service
public class EncoderService {

    /** Base64 gorunumlu, en az 16 karakterlik diziler — ic ice kodlama belirtisi. */
    private static final Pattern OLASI_BASE64 =
            Pattern.compile("^[A-Za-z0-9+/=_-]{16,}$");

    private static final Pattern JWT_BENZERI =
            Pattern.compile("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$");

    /** Cozulen metinde gecerse isaretlenecek anahtar kelimeler. */
    private static final List<String> HASSAS_ANAHTARLAR = List.of(
            "password", "passwd", "secret", "api_key", "apikey", "token",
            "private_key", "authorization", "sifre", "parola");

    public EncodeResponse convert(EncodeRequest request) {
        String input = request.getInput();
        EncodeRequest.Format format = request.getFormat();
        EncodeRequest.Operation operation = request.getOperation();

        byte[] hamVeri;
        String output;

        if (operation == EncodeRequest.Operation.ENCODE) {
            hamVeri = input.getBytes(StandardCharsets.UTF_8);
            output = switch (format) {
                case BASE64 -> Codecs.base64Encode(hamVeri);
                case BASE64URL -> Codecs.base64UrlEncode(hamVeri);
                case HEX -> Codecs.hexEncode(hamVeri);
            };
        } else {
            hamVeri = switch (format) {
                case BASE64 -> Codecs.base64Decode(input);
                case BASE64URL -> Codecs.base64UrlDecode(input);
                case HEX -> Codecs.hexDecode(input);
            };
            String metin = metneCevir(hamVeri);
            // Cozulen veri metin degilse ciktida hex gosterilir; bozuk
            // karakterler basmak yaniltici olurdu.
            output = (metin != null) ? metin : Codecs.hexEncode(hamVeri);
        }

        String asText = metneCevir(hamVeri);
        List<Finding> findings = bulgular(operation, asText, hamVeri);

        return new EncodeResponse(
                output,
                format.name(),
                operation.name(),
                input.length(),
                output.length(),
                hamVeri.length,
                asText,
                Codecs.base64Encode(hamVeri),
                Codecs.base64UrlEncode(hamVeri),
                Codecs.hexEncode(hamVeri),
                findings
        );
    }

    // ------------------------------------------------------------------
    // Bulgular
    // ------------------------------------------------------------------

    private List<Finding> bulgular(EncodeRequest.Operation operation, String metin, byte[] ham) {
        List<Finding> f = new ArrayList<>();

        if (operation != EncodeRequest.Operation.DECODE || metin == null) {
            if (operation == EncodeRequest.Operation.DECODE && metin == null) {
                f.add(Finding.low("Çözülen veri geçerli UTF-8 metin değil; "
                        + "ikili (binary) içerik olabilir. Hex gösterimi kullanıldı."));
            }
            return f;
        }

        String kirpik = metin.trim();

        if (JWT_BENZERI.matcher(kirpik).matches()) {
            f.add(Finding.medium("Çözülen değer JWT yapısında görünüyor "
                    + "(üç nokta ayrılmış bölüm). JWT Token Analyzer ile incelenebilir."));
        } else if (OLASI_BASE64.matcher(kirpik).matches()) {
            f.add(Finding.low("Çözülen değer yine kodlanmış görünüyor; "
                    + "iç içe kodlama olabilir, bir kez daha çözmeyi deneyin."));
        }

        String kucuk = kirpik.toLowerCase();
        for (String anahtar : HASSAS_ANAHTARLAR) {
            if (kucuk.contains(anahtar)) {
                f.add(Finding.high("Çözülen içerikte '" + anahtar + "' geçiyor; "
                        + "kimlik bilgisi taşıyor olabilir. Base64 şifreleme DEĞİLDİR, "
                        + "yalnızca kodlamadır — gizli veriyi korumaz."));
                break;
            }
        }

        return f;
    }

    // ------------------------------------------------------------------
    // Yardimcilar
    // ------------------------------------------------------------------

    /**
     * Baytlari kati UTF-8 kurallariyla metne cevirir.
     *
     * {@code new String(bytes, UTF_8)} gecersiz baytlari sessizce "?" ile
     * degistirir; bu, ikili veriyi metinmis gibi gostererek kullaniciyi
     * yanilir. Burada kati kod cozucu kullanilip basarisizlikta null
     * donuluyor.
     *
     * @return metin, ya da veri gecerli UTF-8 degilse null
     */
    private String metneCevir(byte[] data) {
        try {
            var decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            return decoder.decode(java.nio.ByteBuffer.wrap(data)).toString();
        } catch (CharacterCodingException ex) {
            return null;
        }
    }
}
