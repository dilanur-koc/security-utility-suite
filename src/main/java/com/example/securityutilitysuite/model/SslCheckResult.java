package com.example.securityutilitysuite.model;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * Bir domain'e ait SSL sertifikasi denetim sonucunu temsil eder.
 * Zamanlanmis bir job (scheduler) tarafindan periyodik olarak doldurulmasi hedeflenir.
 */
@Entity
@Table(name = "ssl_check_results")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SslCheckResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 255)
    private String domain;

    @Column(length = 500)
    private String issuer;

    @Column(name = "valid_from")
    private LocalDateTime validFrom;

    @Column(name = "valid_to")
    private LocalDateTime validTo;

    @Column(name = "days_remaining")
    private long daysRemaining;

    @Column(name = "is_expired")
    private boolean isExpired;

    @Column(name = "checked_at", nullable = false)
    private LocalDateTime checkedAt;

    @PrePersist
    protected void onCreate() {
        if (this.checkedAt == null) {
            this.checkedAt = LocalDateTime.now();
        }
    }
}