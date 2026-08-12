package com.example.securityutilitysuite.security;

import com.example.securityutilitysuite.model.OwnedEntity;
import com.example.securityutilitysuite.model.User;
import com.example.securityutilitysuite.repository.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.NoSuchElementException;

/**
 * Oturumdaki kullaniciyi cozer ve kayit sahipligini denetler.
 *
 * NEDEN MERKEZI:
 * Sahiplik kontrolunu her servise elle yazmak, birinde unutulmasi demektir.
 * Unutulan yer dogrudan bir IDOR acigi olur: saldirgan id'yi tahmin ederek
 * baskasinin kaydini gorebilir veya silebilir. Tek kapidan gecirmek bu riski
 * ortadan kaldirir.
 *
 * GUVENLIK NOTU — neden 404 degil 403 sorusu:
 * {@link #denetle} baskasinin kaydinda {@link AccessDeniedException} yerine
 * {@link NoSuchElementException} firlatir. Boylece "bu id var ama senin
 * degil" ile "bu id hic yok" ayirt edilemez. 403 donmek, saldirgana hangi
 * id'lerin gercekte var oldugunu sizdirirdi (kaynak numaralandirma).
 */
@Component
public class CurrentUserProvider {

    private final UserRepository userRepository;

    public CurrentUserProvider(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Oturumdaki kullaniciyi dondurur.
     *
     * @throws IllegalStateException oturum yoksa (normalde SecurityConfig
     *         bunu engeller; buraya dusmesi bir yapilandirma hatasidir)
     */
    public User current() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new IllegalStateException("Oturum bulunamadı");
        }
        return userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new IllegalStateException(
                        "Oturumdaki kullanıcı veritabanında yok: " + auth.getName()));
    }

    /** Oturumdaki kullanicinin id'si. */
    public Long currentId() {
        return current().getId();
    }

    /**
     * Kaydin oturumdaki kullaniciya ait oldugunu dogrular.
     *
     * @param kayit denetlenecek kayit (null ise "bulunamadi" sayilir)
     * @return kaydin kendisi (zincirlemeye uygun)
     * @throws NoSuchElementException kayit yoksa VEYA baskasina aitse —
     *         ikisi bilerek ayni hatayi verir
     */
    public <T extends OwnedEntity> T denetle(T kayit) {
        if (kayit == null || !kayit.getOwner().getId().equals(currentId())) {
            throw new NoSuchElementException("Kayıt bulunamadı");
        }
        return kayit;
    }

    /** Oturumdaki kullanici ADMIN mi? */
    public boolean isAdmin() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
    }
}
