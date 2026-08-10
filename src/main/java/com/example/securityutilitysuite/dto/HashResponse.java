package com.example.securityutilitysuite.dto;

import java.util.List;
import java.util.Map;

/**
 * Hash islemi sonucu.
 *
 * @param operation       yapilan islem
 * @param digests         algoritma -> hex ozet (HASH isleminde dolu)
 * @param identifiedTypes verilen ozetin uzunluguna gore olasi algoritmalar
 * @param matched         VERIFY sonucu; islem VERIFY degilse null
 * @param matchedAlgorithm eslesmenin hangi algoritmayla saglandigi
 * @param cracked         CRACK sonucunda bulunan acik metin; bulunamadiysa null
 * @param triedWords      denenen sozluk kelimesi sayisi
 * @param findings        guvenlik uyarilari
 */
public record HashResponse(
        String operation,
        Map<String, String> digests,
        List<String> identifiedTypes,
        Boolean matched,
        String matchedAlgorithm,
        String cracked,
        int triedWords,
        List<Finding> findings
) {
}
