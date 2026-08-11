package com.example.securityutilitysuite.dto;

/**
 * POST /api/v1/ioc/extract istek govdesi.
 *
 * @param content IOC aranacak metin (tehdit raporu, log, e-posta basligi vb.)
 *                "1[.]2[.]3[.]4", "hxxp://" gibi defanged (etkisizlestirilmis)
 *                gosterimler otomatik olarak normal hale getirilir.
 */
public record IocExtractRequest(String content) {
}
