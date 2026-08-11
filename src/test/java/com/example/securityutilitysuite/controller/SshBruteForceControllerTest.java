package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.SshAnalyzeResponse;
import com.example.securityutilitysuite.service.SshBruteForceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class SshBruteForceControllerTest {

    private MockMvc mockMvc;
    private SshBruteForceService service;

    @BeforeEach
    void hazirla() {
        service = mock(SshBruteForceService.class);
        mockMvc = MockMvcBuilders.standaloneSetup(new SshBruteForceController(service)).build();
    }

    @Test
    void limitiAsanLogIcerigiDoner400() throws Exception {
        String cokUzun = "a".repeat(500_001);
        String json = "{\"logContent\":\"" + cokUzun + "\"}";

        mockMvc.perform(post("/api/v1/ssh/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest());
    }

    @Test
    void gecerliLogIcerigiDoner200() throws Exception {
        when(service.analyze(any()))
                .thenReturn(new SshAnalyzeResponse(0, 0, 5, List.of(), List.of()));

        mockMvc.perform(post("/api/v1/ssh/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"logContent\":\"Aug 10 sshd[1]: Failed password\"}"))
                .andExpect(status().isOk());
    }
}
