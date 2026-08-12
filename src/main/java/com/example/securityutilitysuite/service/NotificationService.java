package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.NotificationItem;
import com.example.securityutilitysuite.enums.NotificationSeverity;
import com.example.securityutilitysuite.model.Notification;
import com.example.securityutilitysuite.model.User;
import com.example.securityutilitysuite.repository.NotificationRepository;
import com.example.securityutilitysuite.security.CurrentUserProvider;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.NoSuchElementException;

/**
 * Uygulama ici bildirimler.
 *
 * TASARIM KARARI — ne zaman bildirim uretilir:
 * Yalnizca DEGISIKLIK veya SORUN oldugunda. Her kontrolde "her sey yolunda"
 * bildirimi uretmek kullaniciyi kisa surede korlestirir (alarm yorgunlugu)
 * ve gercek uyarilar da gozden kacar. Bu, projede daha once konustugumuz
 * dosya butunlugu uyarilarindaki ayni sorun.
 *
 * Tum sorgular sahip bazlidir; kullanici baskasinin bildirimini goremez
 * ve silemez.
 */
@Service
public class NotificationService {

    private static final int DEFAULT_LIMIT = 50;

    private final NotificationRepository repository;
    private final CurrentUserProvider currentUser;

    public NotificationService(NotificationRepository repository,
                               CurrentUserProvider currentUser) {
        this.repository = repository;
        this.currentUser = currentUser;
    }

    // ------------------------------------------------------------------
    // Olusturma (ic kullanim — zamanlanmis kontrolden cagrilir)
    // ------------------------------------------------------------------

    /**
     * Belirtilen kullanici icin bildirim olusturur.
     *
     * Oturumdan degil, PARAMETREDEN kullanici alir: zamanlanmis gorevde
     * HTTP oturumu yoktur, hedefin sahibi acikca verilmelidir.
     */
    @Transactional
    public void olustur(User sahip, String baslik, String mesaj,
                        NotificationSeverity onem, Long hedefId) {
        Notification n = Notification.builder()
                .title(kirp(baslik, 200))
                .message(kirp(mesaj, 1000))
                .severity(onem)
                .targetId(hedefId)
                .read(false)
                .build();
        n.setOwner(sahip);
        repository.save(n);
    }

    // ------------------------------------------------------------------
    // Okuma
    // ------------------------------------------------------------------

    @Transactional(readOnly = true)
    public List<NotificationItem> listele() {
        return repository.findByOwnerIdOrderByCreatedAtDesc(
                        currentUser.currentId(), PageRequest.of(0, DEFAULT_LIMIT))
                .stream()
                .map(n -> new NotificationItem(
                        n.getId(), n.getTitle(), n.getMessage(),
                        n.getSeverity().name(), n.getTargetId(),
                        n.isRead(), n.getCreatedAt()))
                .toList();
    }

    @Transactional(readOnly = true)
    public long okunmamisSayisi() {
        return repository.countByOwnerIdAndReadFalse(currentUser.currentId());
    }

    // ------------------------------------------------------------------
    // Guncelleme / silme
    // ------------------------------------------------------------------

    @Transactional
    public void okunduIsaretle(Long id) {
        Notification n = repository.findByIdAndOwnerId(id, currentUser.currentId())
                .orElseThrow(() -> new NoSuchElementException("Bildirim bulunamadı"));
        n.setRead(true);
        repository.save(n);
    }

    @Transactional
    public int tumunuOkunduIsaretle() {
        return repository.markAllRead(currentUser.currentId());
    }

    @Transactional
    public void sil(Long id) {
        Notification n = repository.findByIdAndOwnerId(id, currentUser.currentId())
                .orElseThrow(() -> new NoSuchElementException("Bildirim bulunamadı"));
        repository.delete(n);
    }

    @Transactional
    public int tumunuSil() {
        return repository.deleteAllForOwner(currentUser.currentId());
    }

    // ------------------------------------------------------------------

    private String kirp(String metin, int limit) {
        if (metin == null) return "";
        return metin.length() > limit ? metin.substring(0, limit - 1) + "…" : metin;
    }
}
