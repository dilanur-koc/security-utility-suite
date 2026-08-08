package com.example.securityutilitysuite.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Basarisiz giris denemelerini sayar ve esik asilinca gecici kilit uygular.
 *
 * KATMANLI ESIK — neden tek bir sayac yeterli degil:
 *
 * 1. IP + kullanici adi (esik 5): Klasik kaba kuvvet. Bir saldirganin tek
 *    hesaba tek noktadan saldirmasini hizlica durdurur.
 * 2. Yalnizca IP (esik 15): Parola puskurtme (password spraying) — ayni
 *    kaynaktan cok sayida farkli hesap denenmesi.
 * 3. Yalnizca kullanici adi (esik 50): Dagitik saldiri. Esik BILEREK yuksek
 *    tutuldu: dusuk olsaydi herkes 5 yanlis parola gonderip "admin" hesabini
 *    kilitleyebilir, yani mesru kullaniciyi disarida birakan bir hizmet
 *    engelleme saldirisi yapabilirdi.
 *
 * BELLEK SINIRI: Haritalar sinirsiz buyuyemez. Kayit sayisi ust siniri asinca
 * suresi dolmus girdiler temizlenir; yine de doluysa yeni kayit alinmaz.
 * Aksi halde cok sayida farkli anahtar gondererek bellek tuketmek mumkun olurdu.
 */
@Service
public class LoginAttemptService {

    private static final Logger log = LoggerFactory.getLogger(LoginAttemptService.class);

    private static final Duration LOCK_DURATION = Duration.ofMinutes(15);
    private static final Duration ENTRY_TTL = Duration.ofMinutes(30);
    private static final int MAX_ENTRIES = 10_000;

    /** Anahtar turune gore esik degerleri. */
    public enum Scope {
        IP_AND_USER(5),
        IP_ONLY(15),
        USER_ONLY(50);

        private final int esik;

        Scope(int esik) {
            this.esik = esik;
        }

        public int esik() {
            return esik;
        }
    }

    private record Kayit(AtomicInteger deneme, Instant sonGorulme, Instant kilitBitis) {
    }

    private final Map<String, Kayit> kayitlar = new ConcurrentHashMap<>();

    // ------------------------------------------------------------------
    // Genel API
    // ------------------------------------------------------------------

    public void basarili(Scope scope, String deger) {
        if (deger == null || deger.isBlank()) return;
        kayitlar.remove(anahtar(scope, deger));
    }

    /** Basarili giriste ilgili tum sayaclari sifirlar. */
    public void basariliGiris(String ip, String kullaniciAdi) {
        basarili(Scope.IP_AND_USER, birlesik(ip, kullaniciAdi));
        basarili(Scope.IP_ONLY, ip);
        basarili(Scope.USER_ONLY, kullaniciAdi);
    }

    /** Basarisiz giriste tum katmanlarin sayaclarini artirir. */
    public void basarisizGiris(String ip, String kullaniciAdi) {
        artir(Scope.IP_AND_USER, birlesik(ip, kullaniciAdi));
        artir(Scope.IP_ONLY, ip);
        artir(Scope.USER_ONLY, kullaniciAdi);
    }

    /** Herhangi bir katman kilitliyse true. */
    public boolean engelliMi(String ip, String kullaniciAdi) {
        return kilitliMi(Scope.IP_AND_USER, birlesik(ip, kullaniciAdi))
                || kilitliMi(Scope.IP_ONLY, ip)
                || kilitliMi(Scope.USER_ONLY, kullaniciAdi);
    }

    /** En dar katmandaki kalan deneme hakki (arayuzde gostermek icin). */
    public int kalanDeneme(String ip, String kullaniciAdi) {
        Kayit k = kayitlar.get(anahtar(Scope.IP_AND_USER, birlesik(ip, kullaniciAdi)));
        int yapilan = (k == null) ? 0 : k.deneme().get();
        return Math.max(0, Scope.IP_AND_USER.esik() - yapilan);
    }

    // ------------------------------------------------------------------
    // Ic isleyis
    // ------------------------------------------------------------------

    private void artir(Scope scope, String deger) {
        if (deger == null || deger.isBlank()) return;

        String key = anahtar(scope, deger);
        Instant now = Instant.now();

        // compute(): okuma ve yazma tek adimda yapilir. Onceki kod
        // getOrDefault + put kullaniyordu; es zamanli isteklerde denemeler
        // eksik sayilabiliyordu.
        kayitlar.compute(key, (k, mevcut) -> {
            if (mevcut == null) {
                if (kayitlar.size() >= MAX_ENTRIES && !temizle()) {
                    log.warn("Giriş denemesi kaydı sınırına ulaşıldı; yeni anahtar eklenmiyor.");
                    return null;
                }
                return new Kayit(new AtomicInteger(1), now, null);
            }

            int sayi = mevcut.deneme().incrementAndGet();
            Instant kilit = mevcut.kilitBitis();
            if (sayi >= scope.esik() && (kilit == null || now.isAfter(kilit))) {
                kilit = now.plus(LOCK_DURATION);
                log.info("Giriş kilidi uygulandı: {} ({} deneme)", key, sayi);
            }
            return new Kayit(mevcut.deneme(), now, kilit);
        });
    }

    private boolean kilitliMi(Scope scope, String deger) {
        if (deger == null || deger.isBlank()) return false;

        String key = anahtar(scope, deger);
        Kayit k = kayitlar.get(key);
        if (k == null || k.kilitBitis() == null) return false;

        if (Instant.now().isAfter(k.kilitBitis())) {
            kayitlar.remove(key);   // suresi doldu
            return false;
        }
        return true;
    }

    /** Suresi gecmis girdileri siler. @return yer acildiysa true */
    private boolean temizle() {
        Instant sinir = Instant.now().minus(ENTRY_TTL);
        int oncesi = kayitlar.size();
        kayitlar.entrySet().removeIf(e ->
                e.getValue().sonGorulme().isBefore(sinir)
                && (e.getValue().kilitBitis() == null
                    || Instant.now().isAfter(e.getValue().kilitBitis())));
        return kayitlar.size() < oncesi;
    }

    private String anahtar(Scope scope, String deger) {
        return scope.name() + ":" + deger;
    }

    private String birlesik(String ip, String kullaniciAdi) {
        if (ip == null || kullaniciAdi == null) return null;
        return ip + "|" + kullaniciAdi;
    }
}
