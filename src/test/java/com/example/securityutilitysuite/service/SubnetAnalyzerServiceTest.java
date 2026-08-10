package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.SubnetAnalyzeRequest;
import com.example.securityutilitysuite.dto.Finding;
import com.example.securityutilitysuite.dto.SubnetAnalyzeResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link SubnetAnalyzerService} icin birim testleri.
 *
 * Bu servis saf hesaplama yaptigi icin — ag erisimi, veritabani veya zaman
 * bagimliligi yok — sonuclar tamamen deterministik. Bu yuzden sinir
 * durumlarini (/0, /31, /32, isaret biti tasan adresler) eksiksiz
 * dogrulayabiliyoruz.
 */
@DisplayName("SubnetAnalyzerService — subnet hesabi ve MAC analizi")
class SubnetAnalyzerServiceTest {

    private SubnetAnalyzerService service;

    @BeforeEach
    void setUp() {
        service = new SubnetAnalyzerService();
    }

    private SubnetAnalyzeResponse analyze(String cidr) {
        return service.analyze(new SubnetAnalyzeRequest(cidr, null));
    }

    // ==================================================================
    // Temel hesaplama
    // ==================================================================

    @Nested
    @DisplayName("Standart bloklar")
    class Standart {

        @Test
        @DisplayName("/24 bloğu doğru hesaplanır")
        void slash24() {
            SubnetAnalyzeResponse r = analyze("192.168.1.0/24");

            assertThat(r.networkAddress()).isEqualTo("192.168.1.0");
            assertThat(r.broadcastAddress()).isEqualTo("192.168.1.255");
            assertThat(r.firstHost()).isEqualTo("192.168.1.1");
            assertThat(r.lastHost()).isEqualTo("192.168.1.254");
            assertThat(r.subnetMask()).isEqualTo("255.255.255.0");
            assertThat(r.wildcardMask()).isEqualTo("0.0.0.255");
            assertThat(r.totalAddresses()).isEqualTo(256);
            assertThat(r.usableHosts()).isEqualTo(254);
            assertThat(r.scope()).contains("Özel");
        }

        @Test
        @DisplayName("/26 bloğu doğru alt ağa oturur")
        void slash26() {
            SubnetAnalyzeResponse r = analyze("10.0.0.100/26");

            assertThat(r.networkAddress()).isEqualTo("10.0.0.64");
            assertThat(r.broadcastAddress()).isEqualTo("10.0.0.127");
            assertThat(r.firstHost()).isEqualTo("10.0.0.65");
            assertThat(r.lastHost()).isEqualTo("10.0.0.126");
            assertThat(r.usableHosts()).isEqualTo(62);
            assertThat(r.subnetMask()).isEqualTo("255.255.255.192");
        }

        @Test
        @DisplayName("/16 bloğunda toplam ve kullanılabilir sayılar doğru")
        void slash16() {
            SubnetAnalyzeResponse r = analyze("172.16.0.0/16");

            assertThat(r.totalAddresses()).isEqualTo(65536);
            assertThat(r.usableHosts()).isEqualTo(65534);
            assertThat(r.broadcastAddress()).isEqualTo("172.16.255.255");
            assertThat(r.scope()).contains("Özel");
        }

        @Test
        @DisplayName("İkili maske gösterimi doğru üretilir")
        void ikiliMaske() {
            assertThat(analyze("192.168.1.0/24").binaryMask())
                    .isEqualTo("11111111.11111111.11111111.00000000");
            assertThat(analyze("10.0.0.0/8").binaryMask())
                    .isEqualTo("11111111.00000000.00000000.00000000");
        }
    }

    // ==================================================================
    // Sinir durumlari
    // ==================================================================

    @Nested
    @DisplayName("Sınır durumları")
    class Sinirlar {

        @Test
        @DisplayName("/32 tek adres olarak ele alınır, yayın adresi yok")
        void slash32() {
            SubnetAnalyzeResponse r = analyze("8.8.8.8/32");

            assertThat(r.networkAddress()).isEqualTo("8.8.8.8");
            assertThat(r.broadcastAddress()).isNull();
            assertThat(r.firstHost()).isEqualTo("8.8.8.8");
            assertThat(r.lastHost()).isEqualTo("8.8.8.8");
            assertThat(r.totalAddresses()).isEqualTo(1);
            assertThat(r.usableHosts()).isEqualTo(1);
        }

        @Test
        @DisplayName("/31 noktadan noktaya: iki kullanılabilir adres, yayın adresi yok")
        void slash31() {
            SubnetAnalyzeResponse r = analyze("192.168.1.0/31");

            assertThat(r.broadcastAddress()).isNull();
            assertThat(r.firstHost()).isEqualTo("192.168.1.0");
            assertThat(r.lastHost()).isEqualTo("192.168.1.1");
            assertThat(r.usableHosts()).isEqualTo(2);
        }

        @Test
        @DisplayName("/0 tüm adres uzayını kapsar ve kritik bulgu üretir")
        void slash0() {
            SubnetAnalyzeResponse r = analyze("0.0.0.0/0");

            assertThat(r.totalAddresses()).isEqualTo(4294967296L);
            assertThat(r.subnetMask()).isEqualTo("0.0.0.0");
            assertThat(r.findings()).extracting(Finding::severity)
                    .contains("HIGH");
        }

        @Test
        @DisplayName("128 ve üzeri ilk oktet işaret biti taşmasına yol açmaz")
        void isaretBitiTasmasi() {
            // int kullanilsaydi bu adresler negatife doner ve hesap bozulurdu
            SubnetAnalyzeResponse r = analyze("255.255.255.255/32");
            assertThat(r.networkAddress()).isEqualTo("255.255.255.255");

            SubnetAnalyzeResponse r2 = analyze("200.100.50.0/24");
            assertThat(r2.networkAddress()).isEqualTo("200.100.50.0");
            assertThat(r2.broadcastAddress()).isEqualTo("200.100.50.255");
        }

        @Test
        @DisplayName("Ağ adresi olmayan girdi ağ adresine yuvarlanır ve bilgi verilir")
        void agAdresiDegil() {
            SubnetAnalyzeResponse r = analyze("192.168.1.77/24");

            assertThat(r.networkAddress()).isEqualTo("192.168.1.0");
            assertThat(r.findings()).extracting(Finding::message)
                    .anyMatch(msg -> msg.contains("ağ adresi değil"));
        }
    }

    // ==================================================================
    // Kapsam ve sinif
    // ==================================================================

    @Nested
    @DisplayName("Kapsam tespiti")
    class Kapsam {

        @Test
        @DisplayName("RFC 1918 özel aralıkları tanınır")
        void ozelAraliklar() {
            assertThat(analyze("10.1.2.3/8").scope()).contains("Özel");
            assertThat(analyze("172.20.0.0/16").scope()).contains("Özel");
            assertThat(analyze("192.168.0.0/16").scope()).contains("Özel");
        }

        @Test
        @DisplayName("Özel aralık dışındaki komşu bloklar genel sayılır")
        void sinirKomsulari() {
            // 172.15 ve 172.32 ozel aralik DISINDA
            assertThat(analyze("172.15.0.0/16").scope()).isEqualTo("Genel (public)");
            assertThat(analyze("172.32.0.0/16").scope()).isEqualTo("Genel (public)");
            assertThat(analyze("172.16.0.0/16").scope()).contains("Özel");
            assertThat(analyze("172.31.0.0/16").scope()).contains("Özel");
        }

        @Test
        @DisplayName("Loopback, link-local ve multicast ayırt edilir")
        void digerKapsamlar() {
            assertThat(analyze("127.0.0.1/8").scope()).isEqualTo("Loopback");
            assertThat(analyze("169.254.1.1/16").scope()).contains("Link-local");
            assertThat(analyze("224.0.0.1/24").scope()).isEqualTo("Multicast");
            assertThat(analyze("100.64.0.0/10").scope()).contains("Operatör NAT");
        }

        @Test
        @DisplayName("Klasik adres sınıfları doğru atanır")
        void adresSiniflari() {
            assertThat(analyze("10.0.0.0/8").addressClass()).isEqualTo("A");
            assertThat(analyze("172.16.0.0/16").addressClass()).isEqualTo("B");
            assertThat(analyze("192.168.1.0/24").addressClass()).isEqualTo("C");
            assertThat(analyze("224.0.0.1/32").addressClass()).startsWith("D");
        }
    }

    // ==================================================================
    // Gecersiz girdiler
    // ==================================================================

    @Nested
    @DisplayName("Geçersiz girdiler")
    class Gecersiz {

        @Test
        @DisplayName("Bozuk CIDR biçimi reddedilir")
        void bozukBicim() {
            assertThatThrownBy(() -> analyze("192.168.1.0"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("CIDR");

            assertThatThrownBy(() -> analyze("merhaba/24"))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("255 üzeri oktet reddedilir")
        void gecersizOktet() {
            assertThatThrownBy(() -> analyze("192.168.1.300/24"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("0-255");
        }

        @Test
        @DisplayName("32 üzeri önek reddedilir")
        void gecersizOnek() {
            assertThatThrownBy(() -> analyze("192.168.1.0/33"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("0-32");
        }
    }

    // ==================================================================
    // MAC analizi
    // ==================================================================

    @Nested
    @DisplayName("MAC adresi analizi")
    class Mac {

        private SubnetAnalyzeResponse.MacInfo mac(String value) {
            return service.analyze(new SubnetAnalyzeRequest("192.168.1.0/24", value)).mac();
        }

        @Test
        @DisplayName("Farklı ayraçlar aynı normalize sonuca ulaşır")
        void normalizasyon() {
            assertThat(mac("00:1a:2b:3c:4d:5e").address()).isEqualTo("00:1A:2B:3C:4D:5E");
            assertThat(mac("00-1A-2B-3C-4D-5E").address()).isEqualTo("00:1A:2B:3C:4D:5E");
            assertThat(mac("001A2B3C4D5E").address()).isEqualTo("00:1A:2B:3C:4D:5E");
        }

        @Test
        @DisplayName("Bilinen OUI önekinden üretici çözülür")
        void ureticiTespiti() {
            assertThat(mac("08:00:27:11:22:33").vendorHint()).contains("VirtualBox");
            assertThat(mac("00:50:56:11:22:33").vendorHint()).isEqualTo("VMware");
            assertThat(mac("B8:27:EB:11:22:33").vendorHint()).contains("Raspberry");
        }

        @Test
        @DisplayName("Yerel olarak atanmış MAC işaretlenir")
        void yerelAtanmis() {
            // 02 -> ikinci bit set: locally administered
            assertThat(mac("02:00:00:11:22:33").locallyAdministered()).isTrue();
            assertThat(mac("00:1A:2B:3C:4D:5E").locallyAdministered()).isFalse();
        }

        @Test
        @DisplayName("Çoklu yayın biti tespit edilir")
        void multicast() {
            // 01 -> en dusuk bit set: multicast
            assertThat(mac("01:00:5E:11:22:33").multicast()).isTrue();
            assertThat(mac("00:1A:2B:3C:4D:5E").multicast()).isFalse();
        }

        @Test
        @DisplayName("Yerel MAC için uyarı üretilir")
        void yerelMacBulgusu() {
            var r = service.analyze(new SubnetAnalyzeRequest("192.168.1.0/24", "02:00:00:11:22:33"));
            assertThat(r.findings()).extracting(Finding::message)
                    .anyMatch(m -> m.contains("yerel olarak atanmış"));
        }

        @Test
        @DisplayName("Geçersiz MAC reddedilir")
        void gecersizMac() {
            assertThatThrownBy(() -> mac("00:1A:2B:3C:4D"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("MAC");

            assertThatThrownBy(() -> mac("ZZ:1A:2B:3C:4D:5E"))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("MAC verilmezse analiz yapılmaz")
        void macYok() {
            assertThat(analyze("192.168.1.0/24").mac()).isNull();
        }
    }
}
