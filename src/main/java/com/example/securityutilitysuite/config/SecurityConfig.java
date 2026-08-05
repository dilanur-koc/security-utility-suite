package com.example.securityutilitysuite.config;

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
import org.springframework.security.web.util.matcher.RequestMatcher;
import tools.jackson.databind.ObjectMapper;

import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

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
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/login.html",
                                "/css/**",
                                "/js/**"
                        ).permitAll()
                        // Kayit ucu ACIK BIRAKILIR ama kimin kayit olabilecegine
                        // RegistrationService karar verir: sistemde hic kullanici
                        // yoksa (ilk kurulum) serbest, sonrasinda yalnizca ADMIN.
                        // Filtre seviyesinde kapatsaydik ilk kurulum imkansiz olurdu.
                        .requestMatchers("/api/auth/register", "/api/auth/setup-status").permitAll()
                        // h2-console tum veritabanina okuma/yazma erisimi verir.
                        // Onceden "authenticated" yeterliydi; kayit da acik oldugu
                        // icin herkes hesap acip veritabanina ulasabiliyordu.
                        .requestMatchers("/h2-console/**").hasRole("ADMIN")
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login.html")           // kendi giris sayfamiz
                        .loginProcessingUrl("/perform-login") // formun POST edecegi adres
                        .defaultSuccessUrl("/index.html", true) // basarili girişte dashboard'a git
                        .failureUrl("/login.html?error=true")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login.html?logout=true")
                        .permitAll()
                )
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                // h2-console kendini iframe icinde acar; varsayilan X-Frame-Options
                // DENY bunu engelliyordu. SAMEORIGIN, disaridan gomulmeyi hala
                // engeller ama konsolun calismasina izin verir.
                .headers(h -> h.frameOptions(fo -> fo.sameOrigin()))
                // /api/** icin: oturum yoksa 302 + login.html yerine 401 + JSON don.
                // Sayfa istekleri (/index.html vb.) icin eski davranis (login sayfasina
                // yonlendirme) aynen korunuyor.
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
}