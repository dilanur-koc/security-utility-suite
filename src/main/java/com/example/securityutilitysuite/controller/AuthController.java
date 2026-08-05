package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.RegisterRequest;
import com.example.securityutilitysuite.model.User;
import com.example.securityutilitysuite.service.RegistrationService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final RegistrationService registrationService;

    public AuthController(RegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    /**
     * Kullanici olusturur.
     *
     * Sistemde hic kullanici yoksa (ilk kurulum) kayit serbesttir ve olusan
     * hesap ADMIN olur. Sonrasinda yalnizca ADMIN yeni kullanici ekleyebilir;
     * bu kural {@link RegistrationService} icinde uygulanir.
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(
            @Valid @RequestBody RegisterRequest request,
            Authentication authentication) {

        User user = registrationService.kaydet(request, authentication);
        return ResponseEntity.ok(Map.of(
                "message", "Kullanıcı oluşturuldu",
                "username", user.getUsername(),
                "role", user.getRole().name()
        ));
    }

    /**
     * Giris sayfasinin "ilk kurulum" mu yoksa normal giris mi gosterecegini
     * bilmesi icin. Yalnizca boolean doner, kullanici bilgisi sizdirmaz.
     */
    @GetMapping("/setup-status")
    public ResponseEntity<Map<String, Boolean>> setupStatus() {
        return ResponseEntity.ok(Map.of("setupRequired", registrationService.kurulumBekliyor()));
    }

    /** Kayit kapaliyken gelen istek: 403. */
    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<Map<String, String>> kayitKapali(IllegalStateException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "Forbidden", "message", ex.getMessage()));
    }

    /** Kullanici adi cakismasi gibi girdi hatalari: 400. */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> gecersizGirdi(IllegalArgumentException ex) {
        return ResponseEntity.badRequest()
                .body(Map.of("error", "Bad Request", "message", ex.getMessage()));
    }
}
