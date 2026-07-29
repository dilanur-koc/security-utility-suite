package com.example.securityutilitysuite.model;


import com.example.securityutilitysuite.enums.Severity;
import com.example.securityutilitysuite.enums.ThreatType;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * Log analiz motoru tarafindan supheli/tehlikeli olarak isaretlenen
 * bir guvenlik olayini (alert) temsil eder.
 */
@Entity
@Table(name = "security_log_alerts")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecurityLogAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "log_source", length = 255)
    private String logSource;

    @Enumerated(EnumType.STRING)
    @Column(name = "threat_type", nullable = false, length = 30)
    private ThreatType threatType;

    @Lob
    @Column(name = "raw_log", columnDefinition = "TEXT")
    private String rawLog;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Severity severity;

    @Column(name = "detected_at", nullable = false)
    private LocalDateTime detectedAt;

    @PrePersist
    protected void onCreate() {
        if (this.detectedAt == null) {
            this.detectedAt = LocalDateTime.now();
        }
    }
}
