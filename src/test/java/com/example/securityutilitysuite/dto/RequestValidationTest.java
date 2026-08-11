package com.example.securityutilitysuite.dto;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Bu testler Spring context'i baslatmaz — Jakarta Bean Validation'i dogrudan
 * cagirir. Amac hem hizli olmak (agdan/zamandan bagimsiz) hem de doğrulama
 * kurallarini controller/@Valid katmanindan izole test etmek.
 */
class RequestValidationTest {

    private static ValidatorFactory factory;
    private static Validator validator;

    @BeforeAll
    static void kurulum() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @AfterAll
    static void kapat() {
        factory.close();
    }

    // ------------------------------------------------------------------
    // SecretScanRequest
    // ------------------------------------------------------------------

    @Test
    void secretScanRequest_bosIcerikReddedilir() {
        Set<ConstraintViolation<SecretScanRequest>> hatalar =
                validator.validate(new SecretScanRequest(""));
        assertThat(hatalar).isNotEmpty();
    }

    @Test
    void secretScanRequest_500binKarakterUzeriReddedilir() {
        String cokUzun = "a".repeat(500_001);
        Set<ConstraintViolation<SecretScanRequest>> hatalar =
                validator.validate(new SecretScanRequest(cokUzun));
        assertThat(hatalar).isNotEmpty();
    }

    @Test
    void secretScanRequest_gecerliIcerikKabulEdilir() {
        Set<ConstraintViolation<SecretScanRequest>> hatalar =
                validator.validate(new SecretScanRequest("normal metin"));
        assertThat(hatalar).isEmpty();
    }

    // ------------------------------------------------------------------
    // IocExtractRequest
    // ------------------------------------------------------------------

    @Test
    void iocExtractRequest_bosIcerikReddedilir() {
        Set<ConstraintViolation<IocExtractRequest>> hatalar =
                validator.validate(new IocExtractRequest("   "));
        assertThat(hatalar).isNotEmpty();
    }

    @Test
    void iocExtractRequest_500binKarakterUzeriReddedilir() {
        String cokUzun = "a".repeat(500_001);
        Set<ConstraintViolation<IocExtractRequest>> hatalar =
                validator.validate(new IocExtractRequest(cokUzun));
        assertThat(hatalar).isNotEmpty();
    }

    // ------------------------------------------------------------------
    // JwtAnalyzeRequest
    // ------------------------------------------------------------------

    @Test
    void jwtAnalyzeRequest_bosTokenReddedilir() {
        Set<ConstraintViolation<JwtAnalyzeRequest>> hatalar =
                validator.validate(new JwtAnalyzeRequest("", null));
        assertThat(hatalar).isNotEmpty();
    }

    @Test
    void jwtAnalyzeRequest_8binKarakterUzeriTokenReddedilir() {
        String cokUzun = "a".repeat(8_001);
        Set<ConstraintViolation<JwtAnalyzeRequest>> hatalar =
                validator.validate(new JwtAnalyzeRequest(cokUzun, null));
        assertThat(hatalar).isNotEmpty();
    }

    @Test
    void jwtAnalyzeRequest_512KarakterUzeriSecretReddedilir() {
        String cokUzunSecret = "a".repeat(513);
        Set<ConstraintViolation<JwtAnalyzeRequest>> hatalar =
                validator.validate(new JwtAnalyzeRequest("gecerli-token", cokUzunSecret));
        assertThat(hatalar).isNotEmpty();
    }

    @Test
    void jwtAnalyzeRequest_secretNullOlabilir() {
        Set<ConstraintViolation<JwtAnalyzeRequest>> hatalar =
                validator.validate(new JwtAnalyzeRequest("gecerli-token", null));
        assertThat(hatalar).isEmpty();
    }

    // ------------------------------------------------------------------
    // SshAnalyzeRequest
    // ------------------------------------------------------------------

    @Test
    void sshAnalyzeRequest_bosLogIcerigiReddedilir() {
        Set<ConstraintViolation<SshAnalyzeRequest>> hatalar =
                validator.validate(new SshAnalyzeRequest("", 5));
        assertThat(hatalar).isNotEmpty();
    }

    @Test
    void sshAnalyzeRequest_500binKarakterUzeriReddedilir() {
        String cokUzun = "a".repeat(500_001);
        Set<ConstraintViolation<SshAnalyzeRequest>> hatalar =
                validator.validate(new SshAnalyzeRequest(cokUzun, null));
        assertThat(hatalar).isNotEmpty();
    }

    @Test
    void sshAnalyzeRequest_gecerliIcerikKabulEdilir() {
        Set<ConstraintViolation<SshAnalyzeRequest>> hatalar =
                validator.validate(new SshAnalyzeRequest("Aug 10 sshd[1]: Failed password", null));
        assertThat(hatalar).isEmpty();
    }
}
