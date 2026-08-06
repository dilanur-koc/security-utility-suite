package com.example.securityutilitysuite.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * {@link NetworkGuard} icin birim testleri.
 *
 * Tasarim notu — testler bilerek AGDAN BAGIMSIZ tutulmustur:
 * Adresler {@link InetAddress#getByAddress(byte[])} ile dogrudan uretilir,
 * boylece DNS sorgusu yapilmaz. Testte "google.com" gibi gercek bir alan adi
 * cozumlemek, internet olmayan bir makinede veya CI ortaminda kodda hicbir
 * sorun yokken testin kirmizi yanmasina yol acardi.
 */
@DisplayName("NetworkGuard — SSRF koruması")
class NetworkGuardTest {

    private NetworkGuard guard;

    @BeforeEach
    void setUp() {
        guard = new NetworkGuard();
    }

    /** DNS'e gitmeden IPv4 adresi uretir. */
    private static InetAddress ipv4(int a, int b, int c, int d) throws Exception {
        return InetAddress.getByAddress(new byte[]{(byte) a, (byte) b, (byte) c, (byte) d});
    }

    // ==================================================================
    // Engellenmesi gerekenler
    // ==================================================================

    @Nested
    @DisplayName("Engellenen adresler")
    class Engellenen {

        @Test
        @DisplayName("Bulut metadata ucu (169.254.169.254) engellenir")
        void bulutMetadata() throws Exception {
            // SSRF saldirilarinin en degerli hedefi: bulut saglayicilarinin
            // kimlik bilgisi dondurdugu metadata servisi.
            assertThat(guard.isBlocked(ipv4(169, 254, 169, 254))).isTrue();
        }

        @Test
        @DisplayName("Loopback adresleri engellenir")
        void loopback() throws Exception {
            assertThat(guard.isBlocked(ipv4(127, 0, 0, 1))).isTrue();
            assertThat(guard.isBlocked(ipv4(127, 1, 2, 3))).isTrue();
            assertThat(guard.isBlocked(InetAddress.getByName("::1"))).isTrue();
        }

        @Test
        @DisplayName("RFC 1918 özel ağ blokları engellenir")
        void ozelAglar() throws Exception {
            assertThat(guard.isBlocked(ipv4(10, 0, 0, 1))).isTrue();
            assertThat(guard.isBlocked(ipv4(192, 168, 1, 1))).isTrue();
            assertThat(guard.isBlocked(ipv4(172, 16, 0, 1))).isTrue();
            assertThat(guard.isBlocked(ipv4(172, 31, 255, 255))).isTrue();
        }

        @Test
        @DisplayName("Operatör NAT (CGNAT, 100.64.0.0/10) engellenir")
        void cgnat() throws Exception {
            assertThat(guard.isBlocked(ipv4(100, 64, 0, 1))).isTrue();
            assertThat(guard.isBlocked(ipv4(100, 127, 255, 255))).isTrue();
        }

        @Test
        @DisplayName("Any-local ve multicast engellenir")
        void anyLocalVeMulticast() throws Exception {
            assertThat(guard.isBlocked(ipv4(0, 0, 0, 0))).isTrue();
            assertThat(guard.isBlocked(ipv4(224, 0, 0, 1))).isTrue();
        }

        @Test
        @DisplayName("Yerel host adı istisna fırlatır")
        void yerelHostAdi() {
            // 127.0.0.1 duz metin adres; cozumleme icin DNS gerekmez.
            assertThatThrownBy(() -> guard.verifyPublicTarget("127.0.0.1"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("iç ağ");
        }
    }

    // ==================================================================
    // Gecmesi gerekenler
    // ==================================================================

    @Nested
    @DisplayName("İzin verilen adresler")
    class IzinVerilen {

        @Test
        @DisplayName("Genel IPv4 adresleri geçer")
        void genelAdresler() throws Exception {
            assertThat(guard.isBlocked(ipv4(8, 8, 8, 8))).isFalse();
            assertThat(guard.isBlocked(ipv4(1, 1, 1, 1))).isFalse();
            assertThat(guard.isBlocked(ipv4(93, 184, 216, 34))).isFalse();
        }

        @Test
        @DisplayName("Özel blokların hemen dışındaki komşular geçer")
        void sinirKomsulari() throws Exception {
            // 172.16-172.31 ozel; 172.15 ve 172.32 DEGIL.
            assertThat(guard.isBlocked(ipv4(172, 15, 0, 1))).isFalse();
            assertThat(guard.isBlocked(ipv4(172, 32, 0, 1))).isFalse();
            // CGNAT 100.64-100.127; disi genel.
            assertThat(guard.isBlocked(ipv4(100, 63, 0, 1))).isFalse();
            assertThat(guard.isBlocked(ipv4(100, 128, 0, 1))).isFalse();
        }

        @Test
        @DisplayName("Genel IPv6 adresi geçer")
        void genelIpv6() throws Exception {
            assertThat(guard.isBlocked(InetAddress.getByName("2001:4860:4860::8888"))).isFalse();
        }

        @Test
        @DisplayName("Genel IP ile verifyPublicTarget istisna fırlatmaz")
        void genelHedefGecer() {
            // Duz metin adres — DNS sorgusu yapilmaz, test agdan bagimsiz kalir.
            assertThatCode(() -> guard.verifyPublicTarget("8.8.8.8")).doesNotThrowAnyException();
        }
    }

    // ==================================================================
    // Gecersiz girdiler
    // ==================================================================

    @Nested
    @DisplayName("Geçersiz girdiler")
    class Gecersiz {

        @Test
        @DisplayName("Boş veya null host reddedilir")
        void bosHost() {
            assertThatThrownBy(() -> guard.verifyPublicTarget(null))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> guard.verifyPublicTarget("   "))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Çözümlenemeyen host reddedilir")
        void cozumlenemeyenHost() {
            // .invalid RFC 2606 ile ayrilmis; hicbir zaman cozumlenmez.
            assertThatThrownBy(() -> guard.verifyPublicTarget("bulunamaz.invalid"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("çözülemedi");
        }
    }
}
