package com.example.securityutilitysuite.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class VulnerableTestController {

    /**
     * Reflected XSS Zafiyeti Simülasyonu:
     * Gelen 'q' parametresini sanitize etmeden doğrudan HTML yanıtı olarak geri döndürür.
     */
    @GetMapping("/api/test/xss")
    public ResponseEntity<String> testXss(@RequestParam(name = "q", defaultValue = "") String query) {
        String htmlResponse = "<html><body><h1>Arama Sonuçları</h1><p>Aranan kelime: " + query + "</p></body></html>";
        return ResponseEntity.ok().header("Content-Type", "text/html; charset=UTF-8").body(htmlResponse);
    }

    /**
     * SQL Injection Hata İmzası Simülasyonu:
     * Parametrede tırnak işareti (') görünce veritabanı hatası taklidi yapar.
     */
    @GetMapping("/api/test/sqli")
    public ResponseEntity<String> testSqli(@RequestParam(name = "id", defaultValue = "") String id) {
        if (id.contains("'")) {
            return ResponseEntity.status(500)
                    .body("Internal Server Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1");
        }
        return ResponseEntity.ok("Kullanıcı Detayı: " + id);
    }
}