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
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
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
    private final ClientIpResolver clientIpResolver;

    public SecurityConfig(LoginAttemptService loginAttemptService,
                          ClientIpResolver clientIpResolver) {
        this.loginAttemptService = loginAttemptService;
        this.clientIpResolver = clientIpResolver;
    }

    /**
     * /api/** eslesmesi. getServletPath() bazi servlet yapilandirmalarinda
     * bos donebildigi icin getRequestURI() kullaniliyor; baglam yolu varsa
     * onu da hesaba katar.
     */
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
                // CSRF korumasi ACIK. Uygulama oturum cerezi (JSESSIONID) ile
                // kimlik dogruladigi icin, koruma olmadan baska bir site
                // kullanicinin tarayicisina bizim adimiza POST yaptirabilirdi
                // (orn. onun oturumuyla tarama baslatmak).
                //
                // Token cerezde tasinir (XSRF-TOKEN, HttpOnly degil) ki arayuz
                // JavaScript'i okuyup X-XSRF-TOKEN basligiyla geri gonderebilsin.
                //
                // Duz isleyici kullaniliyor: Spring'in varsayilan XOR'lu
                // isleyicisinde cerezdeki HAM token ile sunucunun bekledigi
                // deger farkli olur ve arayuzden gelen her POST 403 donerdi.
                // Odunc: BREACH'e karsi ek karistirma yok; yerel kullanim
                // icin kabul edilebilir.
                //
                // h2-console kendi formlarini gonderdigi ve token ekleyemedigi
                // icin kapsam disi; zaten yalnizca ADMIN erisebiliyor.
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                        .ignoringRequestMatchers("/h2-console/**")
                )
                // Spring token'i "gerektiginde" uretir; o durumda sayfa ilk
                // yuklendiginde cerez olusmaz ve ilk POST basarisiz olurdu.
                // Bu filtre token'i her istekte zorla uretir.
                .addFilterAfter(new CsrfCookieFilter(), CsrfFilter.class)
                // BRUTE-FORCE RATE LIMITING FILTRESI
                .addFilterBefore(new LoginRateLimitFilter(loginAttemptService, clientIpResolver, objectMapper),
                        UsernamePasswordAuthenticationFilter.class)
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

    }

    /**
     * CSRF token'ini her istekte zorla uretir.
     *
     * Spring token'i tembel (deferred) uretir: kimse istemezse olusturulmaz
     * ve XSRF-TOKEN cerezi yazilmaz. Arayuz cerezi okumak zorunda oldugu
     * icin, cerez yoksa ilk POST 403 doner.
     */
    private static class CsrfCookieFilter extends OncePerRequestFilter {

        @Override
        protected void doFilterInternal(HttpServletRequest request,
                                        HttpServletResponse response,
                                        FilterChain filterChain)
                throws ServletException, IOException {
            CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
            if (token != null) {
                token.getToken();   // uretimi tetikler, cerez yazilir
            }
            filterChain.doFilter(request, response);
        }
    }
}
