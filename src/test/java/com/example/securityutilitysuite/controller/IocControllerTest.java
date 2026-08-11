package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.IocExtractResponse;
import com.example.securityutilitysuite.service.IocService;
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

class IocControllerTest {

    private MockMvc mockMvc;
    private IocService service;

    @BeforeEach
    void hazirla() {
        service = mock(IocService.class);
        mockMvc = MockMvcBuilders.standaloneSetup(new IocController(service)).build();
    }

    @Test
    void limitiAsanIcerik400Doner() throws Exception {
        String cokUzun = "a".repeat(500_001);
        String json = "{\"content\":\"" + cokUzun + "\"}";

        mockMvc.perform(post("/api/v1/ioc/extract")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest());
    }

    @Test
    void gecerliIcerik200Doner() throws Exception {
        when(service.extract(any())).thenReturn(new IocExtractResponse(0, List.of(), List.of()));

        mockMvc.perform(post("/api/v1/ioc/extract")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"content\":\"8.8.8.8\"}"))
                .andExpect(status().isOk());
    }
}
