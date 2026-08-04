package com.example.securityutilitysuite.dto;

import java.util.List;
import java.util.Map;

/**
 * DNS sorgu ve spoofing analizi sonucu.
 *
 * @param domain     sorgulanan alan adi
 * @param resolved   sistem cozumleyicisinden yanit alinabildi mi
 * @param error      alinamadiysa sebebi
 * @param records    kayit turu -> degerler (A, AAAA, MX, TXT, NS, CNAME, SOA)
 * @param resolvers  farkli genel cozumleyicilerin verdigi yanitlar
 * @param consistent tum cozumleyiciler ayni A kayitlarini mi dondurdu
 * @param reverseLookups A kayitlarinin ters DNS kontrolu
 * @param findings   tespit edilen riskler
 */
public record DnsQueryResponse(
        String domain,
        boolean resolved,
        String error,
        Map<String, List<String>> records,
        List<ResolverAnswer> resolvers,
        boolean consistent,
        List<ReverseLookup> reverseLookups,
        List<Finding> findings
) {

    /**
     * Tek bir genel cozumleyicinin yaniti.
     *
     * @param name       cozumleyici adi (orn. Cloudflare)
     * @param address    cozumleyici IP'si
     * @param aRecords   dondurdugu A kayitlari
     * @param responseMs yanit suresi
     * @param error      sorgu basarisizsa sebebi
     */
    public record ResolverAnswer(String name, String address, List<String> aRecords,
                                 long responseMs, String error) {
    }

    /**
     * Bir IP'nin ters DNS kaydi ve ileri dogrulama sonucu.
     *
     * @param ip               A kaydindaki adres
     * @param ptr              adresin ters DNS karsiligi
     * @param forwardConfirmed ptr adi tekrar cozumlendiginde ayni IP'ye donuyor mu
     */
    public record ReverseLookup(String ip, String ptr, boolean forwardConfirmed) {
    }

    public record Finding(String severity, String message) {
    }

    public static DnsQueryResponse failed(String domain, String error) {
        return new DnsQueryResponse(
                domain, false, error, Map.of(), List.of(), true, List.of(),
                List.of(new Finding("CRITICAL", "Alan adı çözümlenemedi: " + error))
        );
    }
}
