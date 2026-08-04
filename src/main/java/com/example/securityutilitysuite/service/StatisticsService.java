package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.DashboardStatsResponse;
import com.example.securityutilitysuite.enums.IntegrityStatus;
import com.example.securityutilitysuite.enums.Severity;
import com.example.securityutilitysuite.enums.ThreatType;
import com.example.securityutilitysuite.model.FileIntegrityRecord;
import com.example.securityutilitysuite.model.ScanResult;
import com.example.securityutilitysuite.model.SecurityLogAlert;
import com.example.securityutilitysuite.repository.FileIntegrityRecordRepository;
import com.example.securityutilitysuite.repository.ScanResultRepository;
import com.example.securityutilitysuite.repository.SecurityLogAlertRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class StatisticsService {

    private static final int RECENT_ALERTS_LIMIT = 10;
    private static final int TOP_IPS_LIMIT = 10;
    private static final int TOP_HOSTS_LIMIT = 10;
    private static final int TOP_PORTS_LIMIT = 10;
    private static final int RISKY_FILES_LIMIT = 10;

    private final SecurityLogAlertRepository logAlertRepository;
    private final FileIntegrityRecordRepository fileIntegrityRepository;
    private final ScanResultRepository scanResultRepository;

    public StatisticsService(SecurityLogAlertRepository logAlertRepository,
                              FileIntegrityRecordRepository fileIntegrityRepository,
                              ScanResultRepository scanResultRepository) {
        this.logAlertRepository = logAlertRepository;
        this.fileIntegrityRepository = fileIntegrityRepository;
        this.scanResultRepository = scanResultRepository;
    }

    @Transactional(readOnly = true)
    public DashboardStatsResponse getDashboardStats() {
        return new DashboardStatsResponse(
                buildSeverityDistribution(),
                buildThreatTypeDistribution(),
                buildTopRiskyIps(),
                buildRecentCriticalAlerts(),
                buildIntegrityStatusDistribution(),
                buildRiskyFiles(),
                buildTopScannedHosts(),
                buildTopOpenPorts()
        );
    }

    private List<DashboardStatsResponse.SeverityDistributionDTO> buildSeverityDistribution() {
        return logAlertRepository.countGroupedBySeverity().stream()
                .map(row -> new DashboardStatsResponse.SeverityDistributionDTO((Severity) row[0], (Long) row[1]))
                .collect(Collectors.toList());
    }

    private List<DashboardStatsResponse.ThreatTypeDistributionDTO> buildThreatTypeDistribution() {
        return logAlertRepository.countGroupedByThreatType().stream()
                .map(row -> new DashboardStatsResponse.ThreatTypeDistributionDTO((ThreatType) row[0], (Long) row[1]))
                .collect(Collectors.toList());
    }

    private List<DashboardStatsResponse.IpFrequencyDTO> buildTopRiskyIps() {
        return logAlertRepository.countGroupedByIpAddress().stream()
                .limit(TOP_IPS_LIMIT)
                .map(row -> new DashboardStatsResponse.IpFrequencyDTO((String) row[0], (Long) row[1]))
                .collect(Collectors.toList());
    }

    private List<DashboardStatsResponse.RecentAlertDTO> buildRecentCriticalAlerts() {
        List<SecurityLogAlert> alerts = logAlertRepository
                .findTop50BySeverityInOrderByDetectedAtDesc(List.of(Severity.HIGH, Severity.CRITICAL));
        return alerts.stream()
                .limit(RECENT_ALERTS_LIMIT)
                .map(a -> new DashboardStatsResponse.RecentAlertDTO(
                        a.getId(), a.getIpAddress(), a.getThreatType(), a.getSeverity(), a.getDetectedAt()))
                .collect(Collectors.toList());
    }

    private List<DashboardStatsResponse.IntegrityStatusDistributionDTO> buildIntegrityStatusDistribution() {
        return fileIntegrityRepository.countGroupedByStatus().stream()
                .map(row -> new DashboardStatsResponse.IntegrityStatusDistributionDTO((IntegrityStatus) row[0], (Long) row[1]))
                .collect(Collectors.toList());
    }

    private List<DashboardStatsResponse.RiskyFileDTO> buildRiskyFiles() {
        List<FileIntegrityRecord> records = fileIntegrityRepository
                .findByStatusInOrderByLastCheckedAtDesc(List.of(IntegrityStatus.MODIFIED, IntegrityStatus.MISSING));
        return records.stream()
                .limit(RISKY_FILES_LIMIT)
                .map(r -> new DashboardStatsResponse.RiskyFileDTO(r.getFilePath(), r.getStatus(), r.getLastCheckedAt()))
                .collect(Collectors.toList());
    }

    private List<DashboardStatsResponse.HostFrequencyDTO> buildTopScannedHosts() {
        return scanResultRepository.countGroupedByTargetHost().stream()
                .limit(TOP_HOSTS_LIMIT)
                .map(row -> new DashboardStatsResponse.HostFrequencyDTO((String) row[0], (Long) row[1]))
                .collect(Collectors.toList());
    }

    private List<DashboardStatsResponse.PortFrequencyDTO> buildTopOpenPorts() {
        Map<String, Long> portCounts = new HashMap<>();
        // findAll() her dashboard yuklemesinde tum tabloyu bellege cekiyordu.
        // Istatistik icin son 50 tarama yeterli ve maliyeti sabit.
        for (ScanResult scan : scanResultRepository.findTop50ByOrderByCreatedAtDesc()) {
            String openPorts = scan.getOpenPorts();
            if (openPorts == null || openPorts.isBlank()) {
                continue;
            }
            for (String port : openPorts.split(",")) {
                String trimmed = port.trim();
                if (!trimmed.isEmpty()) {
                    portCounts.merge(trimmed, 1L, Long::sum);
                }
            }
        }
        return portCounts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(TOP_PORTS_LIMIT)
                .map(e -> new DashboardStatsResponse.PortFrequencyDTO(e.getKey(), e.getValue()))
                .collect(Collectors.toList());
    }
}
