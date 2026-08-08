package com.example.securityutilitysuite.service;

import com.example.securityutilitysuite.dto.RegisterRequest;
import com.example.securityutilitysuite.enums.Role;
import com.example.securityutilitysuite.model.User;
import com.example.securityutilitysuite.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * {@link RegistrationService} icin birim testleri.
 *
 * Bu servis bir GUVENLIK KURALINI uyguluyor: kayit ucu herkese acikti ve
 * kimlik dogrulamasi olmadan hesap acilabiliyordu. Yeni kural, sistemde hic
 * kullanici yoksa (ilk kurulum) kayda izin verir ve o hesabi ADMIN yapar;
 * sonrasinda yalnizca ADMIN yeni kullanici ekleyebilir.
 *
 * Kural sessizce gevserse acik geri gelir, bu yuzden her dal ayri test edilir.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("RegistrationService — kayıt politikası")
class RegistrationServiceTest {

    @Mock
    private UserRepository userRepository;

    private PasswordEncoder passwordEncoder;
    private RegistrationService service;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        service = new RegistrationService(userRepository, passwordEncoder);
        lenient().when(userRepository.existsByUsername(anyString())).thenReturn(false);
        lenient().when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
    }

    private RegisterRequest istek(String kullanici) {
        return new RegisterRequest(kullanici, "Sifre123456", null);
    }

    /** Belirtilen role sahip, kimligi dogrulanmis bir kullanici uretir. */
    private Authentication kimlik(String rol) {
        return new UsernamePasswordAuthenticationToken(
                "biri", "sifre", List.of(new SimpleGrantedAuthority(rol)));
    }

    // ==================================================================
    // Ilk kurulum
    // ==================================================================

    @Nested
    @DisplayName("İlk kurulum")
    class IlkKurulum {

        @Test
        @DisplayName("Hiç kullanıcı yokken kurulum bekliyor durumu bildirilir")
        void kurulumBekliyor() {
            org.mockito.Mockito.when(userRepository.count()).thenReturn(0L);
            assertThat(service.kurulumBekliyor()).isTrue();
        }

        @Test
        @DisplayName("Kullanıcı varken kurulum beklemiyor")
        void kurulumBitmis() {
            org.mockito.Mockito.when(userRepository.count()).thenReturn(3L);
            assertThat(service.kurulumBekliyor()).isFalse();
        }

        @Test
        @DisplayName("İlk kullanıcı kimlik doğrulaması olmadan oluşturulabilir ve ADMIN olur")
        void ilkKullaniciAdminOlur() {
            org.mockito.Mockito.when(userRepository.count()).thenReturn(0L);

            User olusan = service.kaydet(istek("admin"), null);

            assertThat(olusan.getRole()).isEqualTo(Role.ADMIN);
            assertThat(olusan.getUsername()).isEqualTo("admin");
        }
    }

    // ==================================================================
    // Kurulum sonrasi kilit
    // ==================================================================

    @Nested
    @DisplayName("Kurulum sonrası kayıt kilidi")
    class KayitKilidi {

        @Test
        @DisplayName("Anonim istek reddedilir")
        void anonimReddedilir() {
            org.mockito.Mockito.when(userRepository.count()).thenReturn(1L);

            assertThatThrownBy(() -> service.kaydet(istek("yeni"), null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Kayıt kapalı");

            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("USER rolündeki kullanıcı yeni hesap açamaz")
        void userReddedilir() {
            org.mockito.Mockito.when(userRepository.count()).thenReturn(1L);

            assertThatThrownBy(() -> service.kaydet(istek("yeni"), kimlik("ROLE_USER")))
                    .isInstanceOf(IllegalStateException.class);

            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("ADMIN yeni hesap açabilir ve açılan hesap USER olur")
        void adminAcabilir() {
            org.mockito.Mockito.when(userRepository.count()).thenReturn(1L);

            User olusan = service.kaydet(istek("calisan"), kimlik("ROLE_ADMIN"));

            // Yetki yukselmesi olmamali: ADMIN'in actigi hesap ADMIN degil USER.
            assertThat(olusan.getRole()).isEqualTo(Role.USER);
        }
    }

    // ==================================================================
    // Girdi ve parola
    // ==================================================================

    @Nested
    @DisplayName("Girdi doğrulama ve parola")
    class Girdi {

        @Test
        @DisplayName("Var olan kullanıcı adı reddedilir")
        void kullaniciAdiCakismasi() {
            org.mockito.Mockito.when(userRepository.count()).thenReturn(0L);
            org.mockito.Mockito.when(userRepository.existsByUsername("admin")).thenReturn(true);

            assertThatThrownBy(() -> service.kaydet(istek("admin"), null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("zaten alınmış");

            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("Parola düz metin saklanmaz, BCrypt ile özetlenir")
        void parolaHashlenir() {
            org.mockito.Mockito.when(userRepository.count()).thenReturn(0L);

            service.kaydet(istek("admin"), null);

            ArgumentCaptor<User> yakalanan = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(yakalanan.capture());

            String saklanan = yakalanan.getValue().getPassword();
            assertThat(saklanan).isNotEqualTo("Sifre123456");
            assertThat(saklanan).startsWith("$2");   // BCrypt oneki
            assertThat(passwordEncoder.matches("Sifre123456", saklanan)).isTrue();
        }
    }
}
