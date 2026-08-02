package com.example.securityutilitysuite.controller;

import com.example.securityutilitysuite.dto.RegisterRequest;
import com.example.securityutilitysuite.enums.Role;
import com.example.securityutilitysuite.model.User;
import com.example.securityutilitysuite.repository.UserRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Bu kullanici adi zaten alinmis"));
        }

        User user = User.builder()
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                .email(request.email())
                .role(Role.USER)
                .build();

        userRepository.save(user);
        return ResponseEntity.ok(Map.of("message", "Kullanici olusturuldu", "username", user.getUsername()));
    }
}
