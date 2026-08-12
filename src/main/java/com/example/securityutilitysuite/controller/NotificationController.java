package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.NotificationItem;
import com.example.securityutilitysuite.service.NotificationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * Uygulama ici bildirimler. Tum islemler oturumdaki kullaniciyla sinirlidir.
 */
@RestController
@RequestMapping("/api/v1/notifications")
public class NotificationController {

    private final NotificationService notificationService;

    public NotificationController(NotificationService notificationService) {
        this.notificationService = notificationService;
    }

    @GetMapping
    public ResponseEntity<List<NotificationItem>> listele() {
        return ResponseEntity.ok(notificationService.listele());
    }

    @GetMapping("/unread-count")
    public ResponseEntity<Map<String, Long>> okunmamisSayisi() {
        return ResponseEntity.ok(Map.of("count", notificationService.okunmamisSayisi()));
    }

    @PostMapping("/{id}/read")
    public ResponseEntity<Void> okunduIsaretle(@PathVariable Long id) {
        notificationService.okunduIsaretle(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/read-all")
    public ResponseEntity<Map<String, Integer>> tumunuOkunduIsaretle() {
        return ResponseEntity.ok(Map.of("updated", notificationService.tumunuOkunduIsaretle()));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> sil(@PathVariable Long id) {
        notificationService.sil(id);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping
    public ResponseEntity<Map<String, Integer>> tumunuSil() {
        return ResponseEntity.ok(Map.of("deleted", notificationService.tumunuSil()));
    }

    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<Map<String, String>> bulunamadi(NoSuchElementException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", "Not Found", "message", ex.getMessage()));
    }
}
