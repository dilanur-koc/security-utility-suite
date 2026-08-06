package com.example.securityutilitysuite.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank @Size(min = 3, max = 50) String username,
        @NotBlank @Size(min = 8, max = 64, message = "Şifre en az 8 karakter olmalıdır") String password,
        @Email String email
) {
}
