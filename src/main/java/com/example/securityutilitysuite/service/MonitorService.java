package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.DnsQueryRequest;
import com.example.securityutilitysuite.dto.DnsQueryResponse;
import com.example.securityutilitysuite.dto.Finding;
import com.example.securityutilitysuite.dto.HeaderAuditRequest;
import com.example.securityutilitysuite.dto.HeaderAuditResponse;
import com.example.securityutilitysuite.dto.MonitorCheckItem;
import com.example.securityutilitysuite.dto.MonitorTargetItem;
import com.example.securityutilitysuite.dto.MonitorTargetRequest;
import com.example.securityutilitysuite.dto.SslCheckRequest;
import com.example.securityutilitysuite.dto.SslCheckResponse;
import com.example.securityutilitysuite.enums.MonitorType;
import com.example.securityutilitysuite.enums.NotificationSeverity;
import com.example.securityutilitysuite.model.MonitorCheck;
import com.example.securityutilitysuite.model.MonitoredTarget;
import com.example.securityutilitysuite.repository.MonitorCheckRepository;
import com.example.securityutilitysuite.repository.MonitoredTargetRepository;
import com.example.securityutilitysuite.security.CurrentUserProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;
import java.util.NoSuchElementException;

/**
 * Izlenen hedeflerin yonetimi ve periyodik kontrolu.
 *
 * TASARIM KARARLARI:
 *
 * 1. Kontroller MEVCUT modulleri yeniden kullanir (SSL Inspector, HTTP
 *    Headers, DNS Resolver). Ayni mantigi ikinci kez yazmak, birinde
 *    yapilan duzeltmenin digerine gecmemesi demekti — projede bunu
 *    {@code kisaHata} ile yasadik.
 *
 * 2. Sahiplik SORGU SEVIYESINDE uygulanir: {@code findByIdAndOwnerId}
 *    kullanilir, once cek-sonra kontrol et yapilmaz. Kontrolu yazmayi
 *    unutmak boylece imkansiz hale gelir.
 *
 * 3. Degisiklik tespiti son ozetin karsilastirilmasiyla yapilir. Tum
 *    gecmisi karsilastirmaya gerek yok; onemli olan "bir onceki kontrole
 *    gore ne degisti".
 *
 * 4. Bildirim YALNIZCA degisiklik veya sorun oldugunda uretilir. Her
 *    kontrolde bildirim uretmek alarm yorgunlugu yaratirdi.
 */
@Service
public class MonitorService {

    private static final Logger log = LoggerFactory.getLogger(MonitorService.class);

    /** Kullanici basina izlenebilecek azami hedef sayisi. */
    private static final int MAX_TARGETS_PER_USER = 50;

    /** Hedef basina saklanacak gecmis kaydi sayisi. */
    private static final int HISTORY_KEEP = 100;

    /** Ust uste bu kadar basarisiz kontrolden sonra uyarilir. */
    private static final int FAILURE_ALERT_THRESHOLD = 3;

    private final MonitoredTargetRepository targetRepository;
    private final MonitorCheckRepository checkRepository;
    private final NotificationService notificationService;
    private final CurrentUserProvider currentUser;

    private final SslInspectorService sslService;
    private final HttpHeaderAuditService headerService;
    private final DnsResolverService dnsService;

    public MonitorService(MonitoredTargetRepository targetRepository,
                          MonitorCheckRepository checkRepository,
                          NotificationService notificationService,
                          CurrentUserProvider currentUser,
                          SslInspectorService sslService,
                          HttpHeaderAuditService headerService,
                          DnsResolverService dnsService) {
        this.targetRepository = targetRepository;
        this.checkRepository = checkRepository;
        this.notificationService = notificationService;
        this.currentUser = currentUser;
        this.sslService = sslService;
        this.headerService = headerService;
        this.dnsService = dnsService;
    }

    // ------------------------------------------------------------------
    // Hedef yonetimi
    // ------------------------------------------------------------------

    @Transactional
    public MonitorTargetItem ekle(MonitorTargetRequest request) {
        Long sahipId = currentUser.currentId();
        String hedef = request.target().trim();

        if (targetRepository.countByOwnerId(sahipId) >= MAX_TARGETS_PER_USER) {
            throw new IllegalArgumentException(
                    "En fazla " + MAX_TARGETS_PER_USER + " hedef izlenebilir.");
        }
        if (targetRepository.existsByOwnerIdAndTargetAndType(sahipId, hedef, request.type())) {
            throw new IllegalArgumentException("Bu hedef zaten bu türde izleniyor.");
        }

        MonitoredTarget t = MonitoredTarget.builder()
                .target(hedef)
                .type(request.type())
                .active(true)
                .failureCount(0)
                .build();
        t.setOwner(currentUser.current());

        return donustur(targetRepository.save(t));
    }

    @Transactional(readOnly = true)
    public List<MonitorTargetItem> listele() {
        return targetRepository.findByOwnerIdOrderByCreatedAtDesc(currentUser.currentId())
                .stream().map(this::donustur).toList();
    }

    @Transactional
    public void sil(Long id) {
        MonitoredTarget t = bul(id);
        // Gecmis once silinir: yabanci anahtar kisiti nedeniyle sirasi onemli.
        checkRepository.deleteByTargetId(t.getId());
        targetRepository.delete(t);
    }

    @Transactional
    public MonitorTargetItem durumDegistir(Long id) {
        MonitoredTarget t = bul(id);
        t.setActive(!t.isActive());
        return donustur(targetRepository.save(t));
    }

    @Transactional(readOnly = true)
    public List<MonitorCheckItem> gecmis(Long targetId) {
        // Sahiplik sorgunun icinde dogrulanir.
        return checkRepository.findHistory(targetId, currentUser.currentId(),
                        PageRequest.of(0, HISTORY_KEEP))
                .stream()
                .map(c -> new MonitorCheckItem(c.getId(), c.getCheckedAt(), c.getSummary(),
                        c.getSeverity(), c.getFindingCount(), c.isSuccessful(), c.isChanged()))
                .toList();
    }

    /** Kullanicinin istegiyle tek hedefi hemen kontrol eder. */
    @Transactional
    public MonitorTargetItem simdiKontrolEt(Long id) {
        MonitoredTarget t = bul(id);
        kontrolEt(t);
        return donustur(targetRepository.save(t));
    }

    // ------------------------------------------------------------------
    // Kontrol mantigi (zamanlanmis gorev de burayi kullanir)
    // ------------------------------------------------------------------

    /**
     * Tek bir hedefi kontrol eder, gecmise yazar ve gerekirse bildirim uretir.
     *
     * Bu metot HTTP oturumu olmadan da calisabilmeli (zamanlanmis gorev),
     * bu yuzden kullaniciyi oturumdan degil hedefin sahibinden alir.
     */
    @Transactional
    public void kontrolEt(MonitoredTarget t) {
        Sonuc sonuc;
        try {
            sonuc = switch (t.getType()) {
                case SSL -> sslKontrol(t.getTarget());
                case HTTP_HEADERS -> headerKontrol(t.getTarget());
                case DNS -> dnsKontrol(t.getTarget());
                case PHISHING -> new Sonuc("Bu tür için otomatik kontrol henüz yok", "INFO", 0, false);
            };
        } catch (Exception ex) {
            log.warn("Kontrol basarisiz hedef={} tur={}: {}", t.getTarget(), t.getType(), ex.getMessage());
            sonuc = new Sonuc("Kontrol başarısız: " + kisa(ex.getMessage()), "INFO", 0, false);
        }

        boolean degisti = t.getLastSummary() != null && !t.getLastSummary().equals(sonuc.ozet());

        checkRepository.save(MonitorCheck.builder()
                .target(t)
                .checkedAt(LocalDateTime.now())
                .summary(sonuc.ozet())
                .severity(sonuc.onem())
                .findingCount(sonuc.bulguSayisi())
                .successful(sonuc.basarili())
                .changed(degisti)
                .build());

        t.setLastCheckedAt(LocalDateTime.now());
        t.setLastSummary(sonuc.ozet());
        t.setLastSeverity(sonuc.onem());
        t.setFailureCount(sonuc.basarili() ? 0 : t.getFailureCount() + 1);

        bildirimUret(t, sonuc, degisti);
        gecmisiKirp(t);
    }

    /**
     * Bildirim kurallari:
     * - Onem CRITICAL veya HIGH ise her zaman
     * - Sonuc bir oncekinden farkliysa
     * - Ust uste esik kadar basarisizsa
     * Aksi halde bildirim URETILMEZ (alarm yorgunlugunu onlemek icin).
     */
    private void bildirimUret(MonitoredTarget t, Sonuc sonuc, boolean degisti) {
        boolean ciddi = "CRITICAL".equals(sonuc.onem()) || "HIGH".equals(sonuc.onem());
        boolean surekliHata = !sonuc.basarili() && t.getFailureCount() >= FAILURE_ALERT_THRESHOLD;

        if (!ciddi && !degisti && !surekliHata) {
            return;
        }

        String baslik;
        NotificationSeverity onem;

        if (surekliHata) {
            baslik = t.getTarget() + " — ulaşılamıyor";
            onem = NotificationSeverity.MEDIUM;
        } else if (degisti) {
            baslik = t.getTarget() + " — durum değişti";
            onem = ciddi ? NotificationSeverity.HIGH : NotificationSeverity.MEDIUM;
        } else {
            baslik = t.getTarget() + " — sorun tespit edildi";
            onem = NotificationSeverity.valueOf(sonuc.onem());
        }

        notificationService.olustur(t.getOwner(), baslik, sonuc.ozet(), onem, t.getId());
    }

    /** Gecmisi son {@code HISTORY_KEEP} kayitla sinirlar. */
    private void gecmisiKirp(MonitoredTarget t) {
        List<MonitorCheck> kayitlar = checkRepository.findHistory(
                t.getId(), t.getOwner().getId(), PageRequest.of(0, HISTORY_KEEP + 1));
        if (kayitlar.size() > HISTORY_KEEP) {
            LocalDateTime sinir = kayitlar.get(HISTORY_KEEP).getCheckedAt();
            checkRepository.deleteOlderThan(t.getId(), sinir);
        }
    }

    // ------------------------------------------------------------------
    // Tur bazli kontroller — mevcut modulleri yeniden kullanir
    // ------------------------------------------------------------------

    private record Sonuc(String ozet, String onem, int bulguSayisi, boolean basarili) {
    }

    private Sonuc sslKontrol(String hedef) {
        SslCheckResponse r = sslService.inspect(new SslCheckRequest(hedef, 443));
        if (!r.reachable()) {
            return new Sonuc("Bağlanılamadı: " + kisa(r.error()), "INFO", 0, false);
        }
        String ozet = "Sertifika " + r.daysRemaining() + " gün geçerli"
                + (r.expired() ? " (SÜRESİ DOLMUŞ)" : "")
                + (r.trusted() ? "" : ", zincir doğrulanamadı");
        return new Sonuc(ozet, enYuksek(r.findings()), r.findings().size(), true);
    }

    private Sonuc headerKontrol(String hedef) {
        String url = hedef.startsWith("http") ? hedef : "https://" + hedef;
        // HeaderAuditRequest'te parametreli kurucu yok; setter ile dolduruluyor.
        HeaderAuditRequest req = new HeaderAuditRequest();
        req.setUrl(url);
        req.setFollowRedirects(true);
        HeaderAuditResponse r = headerService.audit(req);
        if (!r.reachable()) {
            return new Sonuc("Ulaşılamadı: " + kisa(r.error()), "INFO", 0, false);
        }
        return new Sonuc("Not: " + r.grade() + " (" + r.score() + "/100)",
                enYuksek(r.findings()), r.findings().size(), true);
    }

    private Sonuc dnsKontrol(String hedef) {
        DnsQueryResponse r = dnsService.query(new DnsQueryRequest(hedef, true));
        if (!r.resolved()) {
            return new Sonuc("Çözümlenemedi: " + kisa(r.error()), "INFO", 0, false);
        }
        List<String> a = r.records().getOrDefault("A", List.of());
        return new Sonuc("A kayıtları: " + (a.isEmpty() ? "yok" : String.join(", ", a)),
                enYuksek(r.findings()), r.findings().size(), true);
    }

    /** Bulgular icindeki en yuksek onem derecesi. */
    private String enYuksek(List<Finding> bulgular) {
        if (bulgular == null || bulgular.isEmpty()) return "INFO";
        List<String> sira = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW");
        return bulgular.stream()
                .map(Finding::severity)
                .filter(sira::contains)
                .min(Comparator.comparingInt(sira::indexOf))
                .orElse("INFO");
    }

    // ------------------------------------------------------------------

    private MonitoredTarget bul(Long id) {
        return targetRepository.findByIdAndOwnerId(id, currentUser.currentId())
                .orElseThrow(() -> new NoSuchElementException("İzleme hedefi bulunamadı"));
    }

    private MonitorTargetItem donustur(MonitoredTarget t) {
        return new MonitorTargetItem(t.getId(), t.getTarget(), t.getType().name(),
                t.isActive(), t.getLastCheckedAt(), t.getLastSummary(),
                t.getLastSeverity(), t.getFailureCount(), t.getCreatedAt());
    }

    private String kisa(String metin) {
        if (metin == null) return "bilinmiyor";
        return metin.length() > 200 ? metin.substring(0, 200) + "…" : metin;
    }
}
