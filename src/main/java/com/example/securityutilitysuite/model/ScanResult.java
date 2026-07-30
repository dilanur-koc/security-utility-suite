package com.example.securityutilitysuite.model;

import com.example.securityutilitysuite.enums.ScanStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * JPA entity representing the persisted result of a single port scan run.
 *
 * Kept flat/self-contained (no relationships) so it stays friendly to
 * horizontal scaling: each row fully describes one scan, and multiple
 * application instances can write to it concurrently without shared state.
 */
@Entity
@Table(name = "scan_results")
public class ScanResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "target_host", nullable = false, length = 255)
    private String targetHost;

    /**
     * Comma-separated list of open ports (e.g. "22,80,443").
     * Stored as text rather than a child table to keep writes cheap.
     */
    @Lob
    @Column(name = "open_ports")
    private String openPorts;

    @Column(name = "scan_duration_ms")
    private Long scanDurationMs;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private ScanStatus status;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    protected ScanResult() {
        // Required by JPA
    }

    public ScanResult(String targetHost, ScanStatus status) {
        this.targetHost = targetHost;
        this.status = status;
    }

    @PrePersist
    void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
    }

    public Long getId() {
        return id;
    }

    public String getTargetHost() {
        return targetHost;
    }

    public void setTargetHost(String targetHost) {
        this.targetHost = targetHost;
    }

    public String getOpenPorts() {
        return openPorts;
    }

    public void setOpenPorts(String openPorts) {
        this.openPorts = openPorts;
    }

    public Long getScanDurationMs() {
        return scanDurationMs;
    }

    public void setScanDurationMs(Long scanDurationMs) {
        this.scanDurationMs = scanDurationMs;
    }

    public ScanStatus getStatus() {
        return status;
    }

    public void setStatus(ScanStatus status) {
        this.status = status;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ScanResult that)) return false;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}