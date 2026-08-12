package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.MonitorCheckItem;
import com.example.securityutilitysuite.dto.MonitorTargetItem;
import com.example.securityutilitysuite.dto.MonitorTargetRequest;
import com.example.securityutilitysuite.service.MonitorService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * Izleme hedeflerinin yonetimi.
 *
 * GUVENLIK: Tum islemler oturumdaki kullanicinin kendi kayitlariyla
 * sinirlidir; sahiplik denetimi servis katmanindaki sorgularda uygulanir.
 * Baskasinin kaydina erisim denemesi 404 doner (403 degil) — boylece
 * hangi id'lerin var oldugu sizmaz.
 */
@RestController
@RequestMapping("/api/v1/monitor")
public class MonitorController {

    private final MonitorService monitorService;

    public MonitorController(MonitorService monitorService) {
        this.monitorService = monitorService;
    }

    @GetMapping
    public ResponseEntity<List<MonitorTargetItem>> listele() {
        return ResponseEntity.ok(monitorService.listele());
    }

    @PostMapping
    public ResponseEntity<MonitorTargetItem> ekle(@Valid @RequestBody MonitorTargetRequest request) {
        return ResponseEntity.ok(monitorService.ekle(request));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> sil(@PathVariable Long id) {
        monitorService.sil(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/toggle")
    public ResponseEntity<MonitorTargetItem> durumDegistir(@PathVariable Long id) {
        return ResponseEntity.ok(monitorService.durumDegistir(id));
    }

    @PostMapping("/{id}/check")
    public ResponseEntity<MonitorTargetItem> simdiKontrolEt(@PathVariable Long id) {
        return ResponseEntity.ok(monitorService.simdiKontrolEt(id));
    }

    @GetMapping("/{id}/history")
    public ResponseEntity<List<MonitorCheckItem>> gecmis(@PathVariable Long id) {
        return ResponseEntity.ok(monitorService.gecmis(id));
    }

    // ------------------------------------------------------------------

    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<Map<String, String>> bulunamadi(NoSuchElementException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", "Not Found", "message", ex.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> gecersizGirdi(IllegalArgumentException ex) {
        return ResponseEntity.badRequest()
                .body(Map.of("error", "Bad Request", "message", ex.getMessage()));
    }
}
