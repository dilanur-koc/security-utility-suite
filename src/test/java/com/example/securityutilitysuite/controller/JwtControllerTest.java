package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.JwtAnalyzeResponse;
import com.example.securityutilitysuite.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class JwtControllerTest {

    private MockMvc mockMvc;
    private JwtService jwtService;

    @BeforeEach
    void hazirla() {
        jwtService = mock(JwtService.class);
        mockMvc = MockMvcBuilders.standaloneSetup(new JwtController(jwtService)).build();
    }

    @Test
    void limitiAsanTokenDoner400() throws Exception {
        String cokUzun = "a".repeat(8_001);
        String json = "{\"token\":\"" + cokUzun + "\"}";

        mockMvc.perform(post("/api/v1/jwt/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest());
    }

    @Test
    void gecerliTokenDoner200() throws Exception {
        when(jwtService.analyze(any())).thenReturn(JwtAnalyzeResponse.invalid("test"));

        mockMvc.perform(post("/api/v1/jwt/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"gecerli-uzunlukta-bir-token\"}"))
                .andExpect(status().isOk());
    }
}
