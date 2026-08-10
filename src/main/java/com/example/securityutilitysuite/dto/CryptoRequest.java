package com.example.securityutilitysuite.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * POST /api/v1/crypto istek govdesi.
 */
public class CryptoRequest {

    @NotBlank(message = "input boş olamaz")
    @Size(max = 50_000, message = "input en fazla 50.000 karakter olabilir")
    private String input;

    /** AES icin parola. Sezar modunda kullanilmaz. */
    @Size(max = 256, message = "parola çok uzun")
    private String password;

    /** Sezar modunda kaydirma miktari. */
    private int shift = 3;

    @NotNull(message = "algorithm belirtilmeli")
    private Algorithm algorithm;

    @NotNull(message = "operation belirtilmeli")
    private Operation operation;

    public enum Algorithm {
        /** AES-256-GCM: kimlik dogrulamali sifreleme. */
        AES_GCM,
        /** Klasik Sezar kaydirmasi — yalnizca egitim amacli. */
        CAESAR
    }

    public enum Operation {
        ENCRYPT,
        DECRYPT
    }

    public CryptoRequest() {
    }

    public CryptoRequest(String input, String password, int shift,
                         Algorithm algorithm, Operation operation) {
        this.input = input;
        this.password = password;
        this.shift = shift;
        this.algorithm = algorithm;
        this.operation = operation;
    }

    public String getInput() {
        return input;
    }

    public void setInput(String input) {
        this.input = input;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public int getShift() {
        return shift;
    }

    public void setShift(int shift) {
        this.shift = shift;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
    }

    public Operation getOperation() {
        return operation;
    }

    public void setOperation(Operation operation) {
        this.operation = operation;
    }
}
