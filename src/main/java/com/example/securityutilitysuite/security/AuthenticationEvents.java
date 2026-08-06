package com.example.securityutilitysuite.security;

import com.example.securityutilitysuite.service.LoginAttemptService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Component
public class AuthenticationEvents {

    private final LoginAttemptService loginAttemptService;

    public AuthenticationEvents(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        String clientIP = getClientIP();
        String username = event.getAuthentication().getName();
        
        loginAttemptService.loginSucceeded(clientIP);
        loginAttemptService.loginSucceeded(username);
    }

    @EventListener
    public void onFailure(AuthenticationFailureBadCredentialsEvent event) {
        String clientIP = getClientIP();
        String username = (String) event.getAuthentication().getPrincipal();

        loginAttemptService.loginFailed(clientIP);
        loginAttemptService.loginFailed(username);
    }

    private String getClientIP() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes != null) {
            HttpServletRequest request = attributes.getRequest();
            String xfHeader = request.getHeader("X-Forwarded-For");
            if (xfHeader == null || xfHeader.isEmpty()) {
                return request.getRemoteAddr();
            }
            return xfHeader.split(",")[0];
        }
        return "127.0.0.1";
    }
}
