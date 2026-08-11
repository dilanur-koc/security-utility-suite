package com.example.securityutilitysuite.dto;

import java.util.List;

/**
 * POST /api/v1/phishing/check yanit govdesi.
 *
 * @param parsed               URL gecerli bir http/https URL'si olarak ayristirilabildi mi
 * @param url                  girilen ham URL
 * @param scheme               http/https (veya baska)
 * @param host                 host kismi
 * @param ipBased              host bir alan adi degil dogrudan bir IP adresi mi
 * @param punycode             host punycode (xn--) kodlamasi iceriyor mu
 * @param hasUserInfoTrick     URL'de "@" ile kullanici bilgisi (userinfo) var mi
 *                             (klasik "gercek-site.com@kotu-site.com" hilesi)
 * @param suspiciousTld        sik kotuye kullanilan bir TLD ise adi, degilse null
 * @param subdomainDepth       kok alan adi haricindeki alt alan adi seviyesi
 * @param brandKeywordsFound   host icinde gecen ama kok alan adi olmayan marka isimleri
 * @param closestBrandMatch    duzenleme mesafesi 1-2 olan en yakin bilinen marka (yoksa null)
 * @param closestBrandDistance closestBrandMatch icin Levenshtein mesafesi (yoksa null)
 * @param findings             bulgular
 */
public record PhishingCheckResponse(
        boolean parsed,
        String url,
        String scheme,
        String host,
        boolean ipBased,
        boolean punycode,
        boolean hasUserInfoTrick,
        String suspiciousTld,
        int subdomainDepth,
        List<String> brandKeywordsFound,
        String closestBrandMatch,
        Integer closestBrandDistance,
        List<Finding> findings
) {
}
