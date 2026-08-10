package com.example.securityutilitysuite.dto;

import java.util.List;

/**
 * Sifreleme/cozme sonucu.
 *
 * @param output       islem sonucu (sifrelemede Base64, cozmede duz metin)
 * @param algorithm    kullanilan algoritma
 * @param operation    yapilan islem
 * @param keyBits      anahtar uzunlugu (Sezar icin 0)
 * @param outputLength cikti uzunlugu
 * @param details      algoritmaya ozgu teknik ayrintilar
 * @param findings     guvenlik uyarilari
 */
public record CryptoResponse(
        String output,
        String algorithm,
        String operation,
        int keyBits,
        int outputLength,
        List<Detail> details,
        List<Finding> findings
) {

    /**
     * Teknik ayrinti satiri (tuz, IV, iterasyon sayisi gibi).
     *
     * @param label aciklama
     * @param value deger
     */
    public record Detail(String label, String value) {
    }
}
