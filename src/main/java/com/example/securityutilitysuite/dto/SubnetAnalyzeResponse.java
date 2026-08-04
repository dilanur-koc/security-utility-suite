package com.example.securityutilitysuite.dto;

import java.util.List;

/**
 * Subnet hesabi ve MAC analizi sonucu.
 *
 * @param cidr           girilen CIDR gosterimi
 * @param networkAddress ag adresi
 * @param broadcastAddress yayin adresi (/31 ve /32 icin null)
 * @param firstHost      kullanilabilir ilk host
 * @param lastHost       kullanilabilir son host
 * @param subnetMask     noktali ondalik maske
 * @param wildcardMask   ters maske (ACL yazarken kullanilir)
 * @param prefixLength   /24 gibi onek uzunlugu
 * @param totalAddresses bloktaki toplam adres sayisi
 * @param usableHosts    kullanilabilir host sayisi
 * @param addressClass   klasik A/B/C/D/E sinifi
 * @param scope          adresin kapsami (ozel, genel, loopback...)
 * @param binaryMask     maskenin ikili gosterimi
 * @param mac            MAC analizi (istenmediyse null)
 * @param findings       dikkat edilmesi gereken noktalar
 */
public record SubnetAnalyzeResponse(
        String cidr,
        String networkAddress,
        String broadcastAddress,
        String firstHost,
        String lastHost,
        String subnetMask,
        String wildcardMask,
        int prefixLength,
        long totalAddresses,
        long usableHosts,
        String addressClass,
        String scope,
        String binaryMask,
        MacInfo mac,
        List<Finding> findings
) {

    /**
     * MAC adresi analizi.
     *
     * @param address     normalize edilmis MAC
     * @param oui         ilk 3 oktet (uretici oneki)
     * @param vendorHint  bilinen uretici (bulunamazsa null)
     * @param locallyAdministered yerel olarak atanmis mi (rastgelelestirilmis MAC belirtisi)
     * @param multicast   coklu yayin biti set mi
     */
    public record MacInfo(String address, String oui, String vendorHint,
                          boolean locallyAdministered, boolean multicast) {
    }

    public record Finding(String severity, String message) {
    }
}
