package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.Finding;
import com.example.securityutilitysuite.dto.SecretScanResponse;
import com.example.securityutilitysuite.service.SecretLeakService;
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

class SecretLeakControllerTest {

    private MockMvc mockMvc;
    private SecretLeakService service;

    @BeforeEach
    void hazirla() {
        service = mock(SecretLeakService.class);
        mockMvc = MockMvcBuilders.standaloneSetup(new SecretLeakController(service)).build();
    }

    @Test
    void limitiAsanIcerik400Doner() throws Exception {
        String cokUzun = "a".repeat(500_001);
        String json = "{\"content\":\"" + cokUzun + "\"}";

        mockMvc.perform(post("/api/v1/secrets/scan")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest());
    }

    @Test
    void gecerliIcerik200Doner() throws Exception {
        when(service.scan(any()))
                .thenReturn(new SecretScanResponse(1, 0, List.of(), List.of(Finding.low("temiz"))));

        mockMvc.perform(post("/api/v1/secrets/scan")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"content\":\"normal metin\"}"))
                .andExpect(status().isOk());
    }
}
