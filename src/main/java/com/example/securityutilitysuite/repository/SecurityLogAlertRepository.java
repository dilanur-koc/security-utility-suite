package com.example.securityutilitysuite.repository;

import com.example.securityutilitysuite.model.SecurityLogAlert;
import com.example.securityutilitysuite.enums.Severity;
import com.example.securityutilitysuite.enums.ThreatType;
import org.springframework.data.jpa.repository.JpaRepository;
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
}