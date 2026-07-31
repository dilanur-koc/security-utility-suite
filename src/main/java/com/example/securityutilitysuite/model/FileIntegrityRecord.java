package com.example.securityutilitysuite.model;

import com.example.securityutilitysuite.enums.IntegrityStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * JPA entity representing a file being tracked for integrity monitoring.
 *
 * One row per tracked path: the baseline hash is captured once, and every
 * subsequent check updates {@code currentHash}, {@code status}, and
 * {@code lastCheckedAt} in place — the history of individual checks isn't
 * kept as separate rows, keeping this table small and cheap to scan.
 */
@Entity
@Table(name = "file_integrity_records")
public class FileIntegrityRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "file_path", nullable = false, length = 1024)
    private String filePath;

    @Column(name = "algorithm", nullable = false, length = 20)
    private String algorithm;

    @Column(name = "baseline_hash", length = 128)
    private String baselineHash;

    @Column(name = "current_hash", length = 128)
    private String currentHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private IntegrityStatus status;

    @Column(name = "baseline_created_at", nullable = false, updatable = false)
    private LocalDateTime baselineCreatedAt;

    @Column(name = "last_checked_at")
    private LocalDateTime lastCheckedAt;

    protected FileIntegrityRecord() {
        // Required by JPA
    }

    public FileIntegrityRecord(String filePath, String algorithm, String baselineHash) {
        this.filePath = filePath;
        this.algorithm = algorithm;
        this.baselineHash = baselineHash;
        this.currentHash = baselineHash;
        this.status = IntegrityStatus.BASELINE_ONLY;
    }

    @PrePersist
    void onCreate() {
        if (this.baselineCreatedAt == null) {
            this.baselineCreatedAt = LocalDateTime.now();
        }
    }

    public Long getId() {
        return id;
    }

    public String getFilePath() {
        return filePath;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getBaselineHash() {
        return baselineHash;
    }

    public String getCurrentHash() {
        return currentHash;
    }

    public void setCurrentHash(String currentHash) {
        this.currentHash = currentHash;
    }

    public IntegrityStatus getStatus() {
        return status;
    }

    public void setStatus(IntegrityStatus status) {
        this.status = status;
    }

    public LocalDateTime getBaselineCreatedAt() {
        return baselineCreatedAt;
    }

    public LocalDateTime getLastCheckedAt() {
        return lastCheckedAt;
    }

    public void setLastCheckedAt(LocalDateTime lastCheckedAt) {
        this.lastCheckedAt = lastCheckedAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FileIntegrityRecord that)) return false;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
