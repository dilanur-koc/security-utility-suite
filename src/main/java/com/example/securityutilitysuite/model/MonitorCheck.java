package com.example.securityutilitysuite.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Bir izleme hedefinin tek bir kontrol kaydi (gecmis satiri).
 *
 * Sahiplik {@link MonitoredTarget} uzerinden gelir, bu yuzden burada ayri
 * bir {@code owner} alani YOK — ayni bilgiyi iki yerde tutmak, birinin
 * digeriyle tutarsiz kalmasi riskini dogurur. Sorgular hedef uzerinden
 * filtrelenir.
 *
 * Indeks (target_id, checked_at): gecmis her zaman "su hedefin son N
 * kaydi" seklinde sorgulanir.
 */
@Entity
@Table(name = "monitor_checks", indexes = {
        @Index(name = "idx_check_target_time", columnList = "target_id, checked_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MonitorCheck {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "target_id", nullable = false)
    private MonitoredTarget target;

    @Column(name = "checked_at", nullable = false)
    private java.time.LocalDateTime checkedAt;

    /** Kontrolun kisa sonucu (orn. "Not: B, sertifika 45 gun sonra doluyor"). */
    @Column(nullable = false, length = 1000)
    private String summary;

    /** En yuksek onem derecesi. */
    @Column(nullable = false, length = 20)
    private String severity;

    /** Bulunan sorun sayisi. */
    @Column(name = "finding_count", nullable = false)
    private int findingCount;

    /** Kontrol basarili tamamlandi mi (hedefe ulasilamamis olabilir). */
    @Column(nullable = false)
    private boolean successful;

    /** Bir onceki kontrole gore degisiklik oldu mu. */
    @Column(nullable = false)
    private boolean changed;
}
