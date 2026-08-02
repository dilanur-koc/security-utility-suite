package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.DashboardStatsResponse;
import com.example.securityutilitysuite.service.StatisticsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/stats")
public class StatisticsController {

    private final StatisticsService statisticsService;

    public StatisticsController(StatisticsService statisticsService) {
        this.statisticsService = statisticsService;
    }

    @GetMapping("/dashboard")
    public DashboardStatsResponse getDashboardStats() {
        return statisticsService.getDashboardStats();
    }
}
