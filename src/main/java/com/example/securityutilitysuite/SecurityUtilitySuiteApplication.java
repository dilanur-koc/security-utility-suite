package com.example.securityutilitysuite;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class SecurityUtilitySuiteApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityUtilitySuiteApplication.class, args);
    }

    @GetMapping("/api/test")
    public String test() {
        return "Security Utility Suite başarıyla çalışıyor!";
    }
}