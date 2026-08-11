package com.example.securityutilitysuite.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * POST /api/v1/ioc/extract istek govdesi.
 *
 * @param content IOC aranacak metin (tehdit raporu, log, e-posta basligi vb.)
 *                "1[.]2[.]3[.]4", "hxxp://" gibi defanged (etkisizlestirilmis)
 *                gosterimler otomatik olarak normal hale getirilir.
 */
public record IocExtractRequest(
        @NotBlank(message = "İçerik boş olamaz")
        @Size(max = 500_000, message = "İçerik 500.000 karakteri aşamaz")
        String content
) {
}
