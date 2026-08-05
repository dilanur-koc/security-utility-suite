package com.example.securityutilitysuite.util;

/**
 * Istisna mesajlarini kullaniciya gosterilebilir hale getiren yardimcilar.
 *
 * Bu mantik once SSL ve DNS servislerinde birebir ayni sekilde iki kez
 * yazilmisti; tek yerde tutuluyor.
 */
public final class Errors {

    private static final int MAX_LENGTH = 200;

    private Errors() {
        // yardimci sinif
    }

    /**
     * Istisnadan kisa, okunabilir bir mesaj uretir. Mesaj yoksa sinif adina
     * duser, cok uzunsa kirpar.
     */
    public static String kisa(Throwable ex) {
        if (ex == null) {
            return "bilinmeyen hata";
        }
        String msg = ex.getMessage();
        if (msg == null || msg.isBlank()) {
            return ex.getClass().getSimpleName();
        }
        return msg.length() > MAX_LENGTH ? msg.substring(0, MAX_LENGTH) + "…" : msg;
    }
}
