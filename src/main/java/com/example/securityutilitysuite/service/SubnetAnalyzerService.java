package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.SubnetAnalyzeRequest;
import com.example.securityutilitysuite.dto.SubnetAnalyzeResponse;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * IPv4 subnet hesaplayici ve MAC adresi analizcisi.
 *
 * Tasarim notlari:
 * - Tamamen saf hesaplama: ag erisimi yok, veritabani yok, dis bagimlilik yok.
 *   Bu sayede sonuclar deterministik ve birim testiyle tam dogrulanabilir.
 * - Adresler 32-bit isaretsiz deger olarak long uzerinde tutulur; int
 *   kullanilsaydi isaret biti 128.0.0.0 ve uzerini negatife cevirirdi.
 * - OUI veritabani gomulu ve kucuktur; amac tam bir uretici listesi sunmak
 *   degil, yaygin ureticileri tanimak ve yerel/rastgele MAC'leri isaretlemektir.
 */
@Service
public class SubnetAnalyzerService {

    private static final Pattern CIDR_PATTERN =
            Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})/(\\d{1,2})$");

    private static final Pattern MAC_PATTERN =
            Pattern.compile("^([0-9A-Fa-f]{2})([:-]?)([0-9A-Fa-f]{2})\\2([0-9A-Fa-f]{2})\\2"
                          + "([0-9A-Fa-f]{2})\\2([0-9A-Fa-f]{2})\\2([0-9A-Fa-f]{2})$");

    /** Yaygin ureticiler. Tam liste degil; tanidiklarini isaretlemek icin. */
    private static final Map<String, String> OUI_DB = Map.ofEntries(
            Map.entry("00:1A:2B", "Ayecom Technology"),
            Map.entry("00:50:56", "VMware"),
            Map.entry("00:0C:29", "VMware"),
            Map.entry("00:05:69", "VMware"),
            Map.entry("08:00:27", "Oracle VirtualBox"),
            Map.entry("52:54:00", "QEMU / KVM"),
            Map.entry("02:42:AC", "Docker"),
            Map.entry("00:16:3E", "Xen"),
            Map.entry("00:15:5D", "Microsoft Hyper-V"),
            Map.entry("00:03:93", "Apple"),
            Map.entry("00:1B:63", "Apple"),
            Map.entry("AC:DE:48", "Apple (özel)"),
            Map.entry("00:1D:7E", "Cisco-Linksys"),
            Map.entry("00:24:D7", "Intel"),
            Map.entry("00:E0:4C", "Realtek"),
            Map.entry("B8:27:EB", "Raspberry Pi Foundation"),
            Map.entry("DC:A6:32", "Raspberry Pi Trading"),
            Map.entry("00:1E:C2", "Apple"),
            Map.entry("F4:F5:E8", "Google"),
            Map.entry("00:26:BB", "Apple")
    );

    public SubnetAnalyzeResponse analyze(SubnetAnalyzeRequest request) {
        String cidr = request.getCidr().trim();
        var m = CIDR_PATTERN.matcher(cidr);
        if (!m.matches()) {
            throw new IllegalArgumentException(
                    "Geçersiz CIDR gösterimi. Beklenen biçim: 192.168.1.0/24");
        }

        int[] octets = new int[4];
        for (int i = 0; i < 4; i++) {
            octets[i] = Integer.parseInt(m.group(i + 1));
            if (octets[i] > 255) {
                throw new IllegalArgumentException("Oktetler 0-255 aralığında olmalı: " + octets[i]);
            }
        }
        int prefix = Integer.parseInt(m.group(5));
        if (prefix > 32) {
            throw new IllegalArgumentException("Önek uzunluğu 0-32 aralığında olmalı: " + prefix);
        }

        long ip = ((long) octets[0] << 24) | ((long) octets[1] << 16)
                | ((long) octets[2] << 8) | octets[3];

        // /0 icin kaydirma tanimsiz olurdu; ayrica ele aliyoruz.
        long mask = (prefix == 0) ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        long network = ip & mask;
        long broadcast = network | (~mask & 0xFFFFFFFFL);
        long total = 1L << (32 - prefix);

        String networkStr = toIp(network);
        String broadcastStr;
        String firstHost;
        String lastHost;
        long usable;

        if (prefix == 32) {
            // Tek adres: ag/yayin kavrami yok
            broadcastStr = null;
            firstHost = networkStr;
            lastHost = networkStr;
            usable = 1;
        } else if (prefix == 31) {
            // RFC 3021: noktadan noktaya baglantilar, yayin adresi yok
            broadcastStr = null;
            firstHost = toIp(network);
            lastHost = toIp(broadcast);
            usable = 2;
        } else {
            broadcastStr = toIp(broadcast);
            firstHost = toIp(network + 1);
            lastHost = toIp(broadcast - 1);
            usable = total - 2;
        }

        SubnetAnalyzeResponse.MacInfo macInfo = null;
        if (request.getMac() != null && !request.getMac().isBlank()) {
            macInfo = analyzeMac(request.getMac().trim());
        }

        List<SubnetAnalyzeResponse.Finding> findings =
                bulgular(ip, network, prefix, usable, macInfo);

        return new SubnetAnalyzeResponse(
                cidr, networkStr, broadcastStr, firstHost, lastHost,
                toIp(mask), toIp(~mask & 0xFFFFFFFFL), prefix,
                total, usable, adresSinifi(octets[0]), kapsam(octets),
                ikiliMaske(mask), macInfo, findings
        );
    }

    // ------------------------------------------------------------------
    // MAC analizi
    // ------------------------------------------------------------------

    private SubnetAnalyzeResponse.MacInfo analyzeMac(String raw) {
        if (!MAC_PATTERN.matcher(raw).matches()) {
            throw new IllegalArgumentException(
                    "Geçersiz MAC adresi. Beklenen biçim: 00:1A:2B:3C:4D:5E");
        }

        String hex = raw.replaceAll("[:-]", "").toUpperCase();
        StringBuilder normalized = new StringBuilder();
        for (int i = 0; i < 12; i += 2) {
            if (i > 0) normalized.append(':');
            normalized.append(hex, i, i + 2);
        }

        String oui = normalized.substring(0, 8);
        int firstOctet = Integer.parseInt(hex.substring(0, 2), 16);

        // IEEE 802: en dusuk anlamli iki bit ozel anlam tasir
        boolean multicast = (firstOctet & 0x01) != 0;
        boolean localAdmin = (firstOctet & 0x02) != 0;

        return new SubnetAnalyzeResponse.MacInfo(
                normalized.toString(), oui, OUI_DB.get(oui), localAdmin, multicast);
    }

    // ------------------------------------------------------------------
    // Bulgular
    // ------------------------------------------------------------------

    private List<SubnetAnalyzeResponse.Finding> bulgular(
            long ip, long network, int prefix, long usable,
            SubnetAnalyzeResponse.MacInfo mac) {

        List<SubnetAnalyzeResponse.Finding> f = new ArrayList<>();

        if (ip != network && prefix < 31) {
            f.add(new SubnetAnalyzeResponse.Finding("LOW",
                    "Girilen adres ağ adresi değil; hesaplama " + toIp(network)
                    + " ağı üzerinden yapıldı."));
        }
        if (prefix <= 8 && prefix > 0) {
            f.add(new SubnetAnalyzeResponse.Finding("MEDIUM",
                    "Çok geniş bir blok (/" + prefix + ", " + usable + " host). "
                    + "Segmentasyon eksikliği yatay hareketi kolaylaştırır."));
        }
        if (prefix == 0) {
            f.add(new SubnetAnalyzeResponse.Finding("HIGH",
                    "/0 tüm IPv4 adres uzayını kapsar. Güvenlik kuralında kullanılıyorsa "
                    + "her yere izin veriyor demektir."));
        }
        if (prefix == 31) {
            f.add(new SubnetAnalyzeResponse.Finding("LOW",
                    "/31 noktadan noktaya bağlantılar içindir (RFC 3021); yayın adresi yoktur."));
        }
        if (prefix == 32) {
            f.add(new SubnetAnalyzeResponse.Finding("LOW",
                    "/32 tek bir adresi ifade eder."));
        }

        if (mac != null) {
            if (mac.locallyAdministered()) {
                f.add(new SubnetAnalyzeResponse.Finding("MEDIUM",
                        "MAC yerel olarak atanmış. Rastgeleleştirilmiş veya elle değiştirilmiş "
                        + "olabilir; MAC tabanlı erişim kontrolü güvenilir değildir."));
            }
            if (mac.multicast()) {
                f.add(new SubnetAnalyzeResponse.Finding("LOW",
                        "MAC çoklu yayın (multicast) biti set; tekil bir cihaz adresi değil."));
            }
            if (mac.vendorHint() == null) {
                f.add(new SubnetAnalyzeResponse.Finding("LOW",
                        "OUI öneki gömülü listede bulunamadı; üretici tespit edilemedi."));
            }
        }

        return f;
    }

    // ------------------------------------------------------------------
    // Yardimcilar
    // ------------------------------------------------------------------

    private String toIp(long value) {
        return ((value >> 24) & 0xFF) + "." + ((value >> 16) & 0xFF) + "."
             + ((value >> 8) & 0xFF) + "." + (value & 0xFF);
    }

    private String ikiliMaske(long mask) {
        StringBuilder sb = new StringBuilder();
        for (int i = 3; i >= 0; i--) {
            if (sb.length() > 0) sb.append('.');
            String bits = Long.toBinaryString((mask >> (i * 8)) & 0xFF);
            sb.append("0".repeat(8 - bits.length())).append(bits);
        }
        return sb.toString();
    }

    /** Klasik (classful) siniflandirma — gunumuzde tarihsel, bilgi amacli. */
    private String adresSinifi(int firstOctet) {
        if (firstOctet < 128) return "A";
        if (firstOctet < 192) return "B";
        if (firstOctet < 224) return "C";
        if (firstOctet < 240) return "D (multicast)";
        return "E (deneysel)";
    }

    private String kapsam(int[] o) {
        if (o[0] == 10) return "Özel (RFC 1918)";
        if (o[0] == 172 && o[1] >= 16 && o[1] <= 31) return "Özel (RFC 1918)";
        if (o[0] == 192 && o[1] == 168) return "Özel (RFC 1918)";
        if (o[0] == 127) return "Loopback";
        if (o[0] == 169 && o[1] == 254) return "Link-local (APIPA)";
        if (o[0] == 100 && o[1] >= 64 && o[1] <= 127) return "Operatör NAT (RFC 6598)";
        if (o[0] >= 224 && o[0] < 240) return "Multicast";
        if (o[0] >= 240) return "Ayrılmış";
        if (o[0] == 0) return "Bu ağ";
        return "Genel (public)";
    }
}
