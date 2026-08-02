package com.example.securityutilitysuite.dto;

import com.example.securityutilitysuite.enums.IntegrityStatus;
import com.example.securityutilitysuite.enums.Severity;
import com.example.securityutilitysuite.enums.ThreatType;

import java.time.LocalDateTime;
import java.util.List;

public record DashboardStatsResponse(
        List<SeverityDistributionDTO> severityDistribution,
        List<ThreatTypeDistributionDTO> threatTypeDistribution,
        List<IpFrequencyDTO> topRiskyIps,
        List<RecentAlertDTO> recentCriticalAlerts,
        List<IntegrityStatusDistributionDTO> integrityStatusDistribution,
        List<RiskyFileDTO> riskyFiles,
        List<HostFrequencyDTO> topScannedHosts,
        List<PortFrequencyDTO> topOpenPorts
) {
    public record SeverityDistributionDTO(Severity severity, long count) {}

    public record ThreatTypeDistributionDTO(ThreatType threatType, long count) {}

    public record IpFrequencyDTO(String ipAddress, long count) {}

    public record RecentAlertDTO(Long id, String ipAddress, ThreatType threatType, Severity severity, LocalDateTime detectedAt) {}

    public record IntegrityStatusDistributionDTO(IntegrityStatus status, long count) {}

    public record RiskyFileDTO(String filePath, IntegrityStatus status, LocalDateTime lastCheckedAt) {}

    public record HostFrequencyDTO(String targetHost, long count) {}

    public record PortFrequencyDTO(String port, long count) {}
}
