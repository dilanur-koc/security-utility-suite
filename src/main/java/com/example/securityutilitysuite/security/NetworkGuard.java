package com.example.securityutilitysuite.security;

import org.springframework.stereotype.Component;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Kullanicinin verdigi hedeflere istek atan modullerin ortak SSRF korumasi.
 *
 * Neden ortak bir bilesen:
 * Bu koruma once yalnizca HTTP Headers modulunde yazilmisti; ayni acik SSL
 * Inspector'da acik kalmisti. Her modulun kendi kopyasini tasimasi, bir
 * sonraki modulde yine unutulmasi demek. Tek yerde tutuluyor ki hedefe
 * baglanan her modul ayni kontrolden gecsin.
 *
 * Kapsam ve sinirlar:
 * - Loopback, link-local (bulut metadata 169.254.169.254 dahil), ozel ag,
 *   any-local, multicast ve CGNAT (100.64.0.0/10) adresleri reddedilir.
 * - Host birden fazla adrese cozumleniyorsa HEPSI kontrol edilir; biri bile
 *   yasakliysa istek reddedilir.
 * - DNS rebinding'e karsi TAM koruma saglamaz: cozumleme ile baglanti
 *   arasinda kayit degisebilir. Bunun icin baglanti anindaki adresi de
 *   dogrulamak gerekir; mevcut kapsamda dogrudan ic adres verilmesi ve
 *   yonlendirme tabanli SSRF engellenir.
 */
@Component
public class NetworkGuard {

    /**
     * Host'u cozumler ve ic/ozel bir adrese isaret ediyorsa istisna firlatir.
     *
     * @throws IllegalArgumentException host cozulemezse veya yasakli bir
     *         adrese cozumlenirse
     */
    public void verifyPublicTarget(String host) {
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("Geçerli bir host belirtilmedi");
        }

        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Host çözülemedi: " + host);
        }

        for (InetAddress addr : addresses) {
            if (isBlocked(addr)) {
                throw new IllegalArgumentException(
                        "Hedef, iç ağ/özel/yerel bir adrese çözümleniyor ("
                        + addr.getHostAddress()
                        + "); güvenlik nedeniyle bu adreslere bağlanılmıyor.");
            }
        }
    }

    /** Adres ic/ozel/yerel bir aralikta mi? */
    public boolean isBlocked(InetAddress addr) {
        if (addr.isLoopbackAddress()        // 127.0.0.0/8, ::1
                || addr.isLinkLocalAddress()   // 169.254.0.0/16 (bulut metadata), fe80::/10
                || addr.isSiteLocalAddress()   // 10/8, 172.16/12, 192.168/16, fc00::/7
                || addr.isAnyLocalAddress()    // 0.0.0.0, ::
                || addr.isMulticastAddress()) {
            return true;
        }
        // 100.64.0.0/10 (Carrier-Grade NAT) — isSiteLocalAddress bunu yakalamaz.
        if (addr instanceof Inet4Address) {
            byte[] b = addr.getAddress();
            int first = b[0] & 0xFF;
            int second = b[1] & 0xFF;
            return first == 100 && second >= 64 && second <= 127;
        }
        return false;
    }
}
