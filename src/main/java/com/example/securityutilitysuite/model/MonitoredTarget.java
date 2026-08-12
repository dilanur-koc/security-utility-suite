package com.example.securityutilitysuite.model;

import com.example.securityutilitysuite.enums.MonitorType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * Duzenli olarak kontrol edilen hedef (site, alan adi).
 *
 * Ayni kullanici ayni hedefi ayni turde iki kez ekleyemez — benzersizlik
 * kisiti (owner_id, target, type) uzerinde. Bu kisit KULLANICI BAZLI:
 * iki farkli kullanici ayni siteyi bagimsiz olarak izleyebilir.
 *
 * {@code lastSummary} son kontrolun ozetini tutar (orn. "Not: B, 45 gun
 * kaldi"). Yeni kontrol bundan farkliysa DEGISIKLIK olmus demektir ve
 * bildirim uretilir — tum gecmisi saklamadan degisiklik tespiti saglar.
 */
@Entity
@Table(name = "monitored_targets", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"owner_id", "target", "type"})
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MonitoredTarget extends OwnedEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Izlenen hedef: alan adi veya URL. */
    @Column(nullable = false, length = 500)
    private String target;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private MonitorType type;

    /** Izleme gecici olarak durdurulabilir; kayit silinmeden. */
    @Column(nullable = false)
    private boolean active;

    @Column(name = "last_checked_at")
    private LocalDateTime lastCheckedAt;

    /** Son kontrolun kisa ozeti; degisiklik tespiti bunun uzerinden yapilir. */
    @Column(name = "last_summary", length = 1000)
    private String lastSummary;

    /** Son kontrolde bulunan en yuksek onem derecesi. */
    @Column(name = "last_severity", length = 20)
    private String lastSeverity;

    /** Ust uste basarisiz kontrol sayisi; surekli hata veren hedefi isaretlemek icin. */
    @Column(name = "failure_count", nullable = false)
    private int failureCount;
}
