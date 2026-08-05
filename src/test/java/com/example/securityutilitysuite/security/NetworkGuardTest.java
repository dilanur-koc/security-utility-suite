package com.example.securityutilitysuite.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class NetworkGuardTest {

    private NetworkGuard networkGuard;

    @BeforeEach
    void setUp() {
        networkGuard = new NetworkGuard();
    }

    @Test
    @DisplayName("SSRF Koruması: Localhost ve İç Ağ Adresleri Engellenmeli")
    void testBlockedInternalAddresses() {
        assertThrows(IllegalArgumentException.class, () -> networkGuard.verifyPublicTarget("127.0.0.1"));
        assertThrows(IllegalArgumentException.class, () -> networkGuard.verifyPublicTarget("localhost"));
    }

    @Test
    @DisplayName("Güvenli Geçiş: Kamuya Açık Alan Adları İzin Almalı")
    void testAllowedPublicAddresses() {
        assertDoesNotThrow(() -> networkGuard.verifyPublicTarget("google.com"));
    }
}
