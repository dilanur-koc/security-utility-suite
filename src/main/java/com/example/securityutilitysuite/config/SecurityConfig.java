package com.example.securityutilitysuite.config;

import com.example.securityutilitysuite.security.ClientIpResolver;
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
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final LoginAttemptService loginAttemptService;
    private final ClientIpResolver clientIpResolver;

    public SecurityConfig(LoginAttemptService loginAttemptService,
                          ClientIpResolver clientIpResolver) {
        this.loginAttemptService = loginAttemptService;
        this.clientIpResolver = clientIpResolver;
    }

    private static final RequestMatcher API_MATCHER = request -> {
        String uri = request.getRequestURI();
        String context = request.getContextPath();
        if (context != null && !context.isEmpty() && uri.startsWith(context)) {
            uri = uri.substring(context.length());
        }
        return uri.startsWith("/api/");
    };

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, ObjectMapper objectMapper) throws Exception {
        AuthenticationEntryPoint apiAuthEntryPoint = jsonAuthEntryPoint(objectMapper);
        AccessDeniedHandler apiAccessDeniedHandler = jsonAccessDeniedHandler(objectMapper);

        http
                // 1. CSRF KORUMASI (Dışarıdan gelen log test istekleri için hem /api/v1/logs/** hem de /api/logs/** hariç tutuldu)
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                        .ignoringRequestMatchers("/h2-console/**", "/api/v1/logs/**", "/api/logs/**")
                )
                .addFilterAfter(new CsrfCookieFilter(), CsrfFilter.class)
                .addFilterBefore(new LoginRateLimitFilter(loginAttemptService, clientIpResolver, objectMapper),
                        UsernamePasswordAuthenticationFilter.class)

                // 2. YETKİLENDİRME (İzinler Yukarıdan Aşağıya Sırayla Okunur)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/login.html",
                                "/css/**",
                                "/js/**"
                        ).permitAll()
                        .requestMatchers("/api/auth/register", "/api/auth/setup-status").permitAll()

                        // 🟢 LOG TEST ENDPOINT'LERİ (anyRequest'ten ÖNCE):
                        .requestMatchers("/api/v1/logs/**", "/api/logs/**").permitAll()

                        .requestMatchers("/h2-console/**").hasRole("ADMIN")
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")

                        // 🛑 anyRequest EN SONDA OLMALI!
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login.html")
                        .loginProcessingUrl("/perform-login")
                        .defaultSuccessUrl("/index.html", true)
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

    private static class LoginRateLimitFilter extends OncePerRequestFilter {

        private final LoginAttemptService loginAttemptService;
        private final ClientIpResolver clientIpResolver;
        private final ObjectMapper objectMapper;

        public LoginRateLimitFilter(LoginAttemptService loginAttemptService,
                                    ClientIpResolver clientIpResolver,
                                    ObjectMapper objectMapper) {
            this.loginAttemptService = loginAttemptService;
            this.clientIpResolver = clientIpResolver;
            this.objectMapper = objectMapper;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                throws ServletException, IOException {

            if ("POST".equalsIgnoreCase(request.getMethod())
                    && request.getRequestURI().endsWith("/perform-login")) {

                String clientIP = clientIpResolver.resolve(request);
                String username = request.getParameter("username");

                if (loginAttemptService.engelliMi(clientIP, username)) {
                    response.setStatus(429);
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

    }

    private static class CsrfCookieFilter extends OncePerRequestFilter {

        @Override
        protected void doFilterInternal(HttpServletRequest request,
                                        HttpServletResponse response,
                                        FilterChain filterChain)
                throws ServletException, IOException {
            CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
            if (token != null) {
                token.getToken();
            }
            filterChain.doFilter(request, response);
        }
    }
}