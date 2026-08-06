package com.example.securityutilitysuite.config;

import com.example.securityutilitysuite.service.LoginAttemptService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final LoginAttemptService loginAttemptService;

    public SecurityConfig(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    /** /api/** icin request.getServletPath() kontrolu - hicbir ozel matcher sinifina bagimli degil. */
    private static final RequestMatcher API_MATCHER =
            request -> request.getServletPath().startsWith("/api/");

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, ObjectMapper objectMapper) throws Exception {
        AuthenticationEntryPoint apiAuthEntryPoint = jsonAuthEntryPoint(objectMapper);
        AccessDeniedHandler apiAccessDeniedHandler = jsonAccessDeniedHandler(objectMapper);

        http
                .csrf(csrf -> csrf.disable()) // API + basit local proje icin kapatiyoruz
                // BRUTE-FORCE RATE LIMITING FILTRESI
                .addFilterBefore(new LoginRateLimitFilter(loginAttemptService, objectMapper), UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/login.html",
                                "/css/**",
                                "/js/**"
                        ).permitAll()
                        // Kayit ucu ACIK BIRAKILIR ama kimin kayit olabilecegine
                        // RegistrationService karar verir: sistemde hic kullanici
                        // yoksa (ilk kurulum) serbest, sonrasinda yalnizca ADMIN.
                        .requestMatchers("/api/auth/register", "/api/auth/setup-status").permitAll()
                        // h2-console tum veritabanina okuma/yazma erisimi verir.
                        .requestMatchers("/h2-console/**").hasRole("ADMIN")
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login.html")           // kendi giris sayfamiz
                        .loginProcessingUrl("/perform-login") // formun POST edecegi adres
                        .defaultSuccessUrl("/index.html", true) // basarili giriste dashboard'a git
                        .failureUrl("/login.html?error=true")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login.html?logout=true")
                        .permitAll()
                )
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .headers(h -> h.frameOptions(fo -> fo.sameOrigin()))
                .exceptionHandling(ex -> ex
                        .defaultAuthenticationEntryPointFor(apiAuthEntryPoint, API_MATCHER)
                        .defaultAccessDeniedHandlerFor(apiAccessDeniedHandler, API_MATCHER)
                );

        return http.build();
    }

    private AuthenticationEntryPoint jsonAuthEntryPoint(ObjectMapper objectMapper) {
        return (request, response, authException) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setCharacterEncoding("UTF-8");
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            objectMapper.writeValue(response.getWriter(), Map.of(
                    "status", 401,
                    "error", "Unauthorized",
                    "message", "Bu isteği yapmak için giriş yapmalısınız."
            ));
        };
    }

    private AccessDeniedHandler jsonAccessDeniedHandler(ObjectMapper objectMapper) {
        return (request, response, accessDeniedException) -> {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setCharacterEncoding("UTF-8");
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            objectMapper.writeValue(response.getWriter(), Map.of(
                    "status", 403,
                    "error", "Forbidden",
                    "message", "Bu işlem için yetkiniz yok."
            ));
        };
    }

    // =========================================================================
    // BRUTE-FORCE ENGELLEME FILTRESI (RATE LIMIT FILTER)
    // =========================================================================
    private static class LoginRateLimitFilter extends OncePerRequestFilter {

        private final LoginAttemptService loginAttemptService;
        private final ObjectMapper objectMapper;

        public LoginRateLimitFilter(LoginAttemptService loginAttemptService, ObjectMapper objectMapper) {
            this.loginAttemptService = loginAttemptService;
            this.objectMapper = objectMapper;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                throws ServletException, IOException {

            if ("POST".equalsIgnoreCase(request.getMethod()) && "/perform-login".equals(request.getServletPath())) {
                String clientIP = getClientIP(request);
                String username = request.getParameter("username");

                if (loginAttemptService.isBlocked(clientIP) || (username != null && loginAttemptService.isBlocked(username))) {
                    response.setStatus(429); // 429 Too Many Requests
                    response.setCharacterEncoding("UTF-8");

                    if (request.getHeader("Accept") != null && request.getHeader("Accept").contains(MediaType.APPLICATION_JSON_VALUE)) {
                        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                        objectMapper.writeValue(response.getWriter(), Map.of(
                                "status", 429,
                                "error", "Too Many Requests",
                                "message", "Çok fazla başarısız giriş denemesi! Hesabınız geçici olarak kilitlendi."
                        ));
                    } else {
                        response.sendRedirect("/login.html?blocked=true");
                    }
                    return;
                }
            }

            filterChain.doFilter(request, response);
        }

        private String getClientIP(HttpServletRequest request) {
            String xfHeader = request.getHeader("X-Forwarded-For");
            if (xfHeader == null || xfHeader.isEmpty()) {
                return request.getRemoteAddr();
            }
            return xfHeader.split(",")[0];
        }
    }
}