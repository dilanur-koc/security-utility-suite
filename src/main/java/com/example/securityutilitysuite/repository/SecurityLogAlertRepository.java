package com.example.securityutilitysuite.repository;

import com.example.securityutilitysuite.model.SecurityLogAlert;
import com.example.securityutilitysuite.enums.Severity;
import com.example.securityutilitysuite.enums.ThreatType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SecurityLogAlertRepository extends JpaRepository<SecurityLogAlert, Long> {

    // Belirli bir tehdit turune gore filtreleme
    List<SecurityLogAlert> findByThreatType(ThreatType threatType);

    // Belirli bir onem derecesine gore filtreleme
    List<SecurityLogAlert> findBySeverity(Severity severity);

    // Belirli bir IP adresine ait tum uyarilari getirir (ornegin brute-force tespiti icin)
    List<SecurityLogAlert> findByIpAddress(String ipAddress);

    // Kritik seviyedeki tum uyarilari en yeniden en eskiye siralar
    List<SecurityLogAlert> findBySeverityOrderByDetectedAtDesc(Severity severity);

    // --- Istatistik Tablosu icin eklenenler ---

    @Query("SELECT s.severity, COUNT(s) FROM SecurityLogAlert s GROUP BY s.severity")
    List<Object[]> countGroupedBySeverity();

    @Query("SELECT s.threatType, COUNT(s) FROM SecurityLogAlert s GROUP BY s.threatType")
    List<Object[]> countGroupedByThreatType();

    @Query("SELECT s.ipAddress, COUNT(s) as cnt FROM SecurityLogAlert s " +
            "WHERE s.ipAddress IS NOT NULL GROUP BY s.ipAddress ORDER BY cnt DESC")
    List<Object[]> countGroupedByIpAddress();

    List<SecurityLogAlert> findTop50BySeverityInOrderByDetectedAtDesc(List<Severity> severities);
}