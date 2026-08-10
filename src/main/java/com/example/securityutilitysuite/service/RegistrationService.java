package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.RegisterRequest;
import com.example.securityutilitysuite.enums.Role;
import com.example.securityutilitysuite.model.User;
import com.example.securityutilitysuite.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Kullanici olusturma kurallari.
 *
 * Neden bu sinif var:
 * Onceden {@code /api/auth/register} herkese aciti. Kimlik dogrulamasi
 * yapmadan hesap acilabildigi icin bir saldirgan (a) uygulamayi kendi
 * hedeflerini taramak icin vekil olarak kullanabiliyor, (b) hesap acip
 * giris yaparak h2-console uzerinden tum veritabanina erisebiliyordu.
 *
 * Yeni kural — "ilk kullanici" akisi:
 * - Sistemde HIC kullanici yoksa kayit serbesttir ve olusan ilk hesap ADMIN olur.
 *   (Kurulum aninda kilitli kalmamak icin.)
 * - Sistemde kullanici varsa kayit yalnizca ADMIN yetkisiyle yapilabilir ve
 *   yeni hesap USER rolunu alir.
 */
@Service
public class RegistrationService {

    private static final Logger log = LoggerFactory.getLogger(RegistrationService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public RegistrationService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /** Sistemde hic kullanici yok mu (ilk kurulum durumu)? */
    @Transactional(readOnly = true)
    public boolean kurulumBekliyor() {
        return userRepository.count() == 0;
    }

    /**
     * @param authentication istegi yapan kullanici; anonim istekte null olabilir
     * @throws IllegalStateException   kayit kapaliysa
     * @throws IllegalArgumentException kullanici adi doluysa
     */

    /**
     * @param authentication istegi yapan kullanici; anonim istekte null olabilir
     * @throws IllegalStateException   kayit kapaliysa
     * @throws IllegalArgumentException kullanici adi doluysa
     *
     * synchronized: kurulumBekliyor() (count()==0 kontrolu) ile save() arasinda
     * bir "check-then-act" araligi var. Bu metod senkronize edilmezse, ayni anda
     * gelen iki ilk-kayit istegi ikisi de count()==0 gorup ikisi de ADMIN
     * olusturabilir. synchronized, ayni JVM icinde istekleri siraya sokarak bunu
     * engeller (uygulama tek instance calistigi surece yeterlidir; coklu
     * instance/cluster senaryosunda bunun yerine DB seviyesinde bir kilit veya
     * unique constraint gerekir).
     */
    @Transactional
    public synchronized User kaydet(RegisterRequest request, Authentication authentication) {
        boolean ilkKullanici = kurulumBekliyor();

        if (!ilkKullanici && !adminMi(authentication)) {
            throw new IllegalStateException(
                    "Kayıt kapalı. Yeni kullanıcıyı yalnızca yönetici oluşturabilir.");
        }

        if (userRepository.existsByUsername(request.username())) {
            throw new IllegalArgumentException("Bu kullanıcı adı zaten alınmış");
        }

        Role rol = ilkKullanici ? Role.ADMIN : Role.USER;

        User user = User.builder()
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                .email(request.email())
                .role(rol)
                .build();

        userRepository.save(user);

        if (ilkKullanici) {
            log.info("İlk kullanıcı oluşturuldu ve ADMIN yetkisi verildi: {}", user.getUsername());
        }
        return user;
    }

    private boolean adminMi(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        return authentication.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
    }
}
