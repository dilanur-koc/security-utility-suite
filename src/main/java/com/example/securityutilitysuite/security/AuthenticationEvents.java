package com.example.securityutilitysuite.security;

import com.example.securityutilitysuite.service.LoginAttemptService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Giris basari/basarisizlik olaylarini dinleyip sayaclari gunceller.
 *
 * IP adresi {@link ClientIpResolver} uzerinden alinir; boylece
 * X-Forwarded-For basligi yalnizca guvenilir bir vekilden geldiginde
 * dikkate alinir. Onceki surumde baslik sorgusuz kabul edildigi icin
 * saldirgan her istekte farkli bir deger gonderip sayaci sifirlayabiliyordu.
 */
@Component
public class AuthenticationEvents {

    private final LoginAttemptService loginAttemptService;
    private final ClientIpResolver clientIpResolver;

    public AuthenticationEvents(LoginAttemptService loginAttemptService,
                                ClientIpResolver clientIpResolver) {
        this.loginAttemptService = loginAttemptService;
        this.clientIpResolver = clientIpResolver;
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        loginAttemptService.basariliGiris(istemciIp(), event.getAuthentication().getName());
    }

    @EventListener
    public void onFailure(AuthenticationFailureBadCredentialsEvent event) {
        Object principal = event.getAuthentication().getPrincipal();
        String kullaniciAdi = (principal instanceof String s) ? s : String.valueOf(principal);
        loginAttemptService.basarisizGiris(istemciIp(), kullaniciAdi);
    }

    private String istemciIp() {
        ServletRequestAttributes attributes =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            return "bilinmiyor";
        }
        HttpServletRequest request = attributes.getRequest();
        return clientIpResolver.resolve(request);
    }
}
