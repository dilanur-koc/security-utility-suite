package com.example.securityutilitysuite.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * POST /api/v1/hash istek govdesi.
 */
public class HashRequest {

    /** HASH islemi icin ozetlenecek metin; VERIFY icin karsilastirilacak metin. */
    @Size(max = 100_000, message = "input en fazla 100.000 karakter olabilir")
    private String input;

    /** VERIFY ve CRACK islemleri icin hedef ozet degeri. */
    @Size(max = 256, message = "hash değeri çok uzun")
    private String hash;

    @NotNull(message = "operation belirtilmeli")
    private Operation operation;

    public enum Operation {
        /** Girdinin tum algoritmalarla ozetini hesaplar. */
        HASH,
        /** Girdinin ozetinin verilen hash ile eslesip eslesmedigine bakar. */
        VERIFY,
        /** Gomulu sozlukle ozeti kirmayi dener. */
        CRACK
    }

    public HashRequest() {
    }

    public HashRequest(String input, String hash, Operation operation) {
        this.input = input;
        this.hash = hash;
        this.operation = operation;
    }

    public String getInput() {
        return input;
    }

    public void setInput(String input) {
        this.input = input;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public Operation getOperation() {
        return operation;
    }

    public void setOperation(Operation operation) {
        this.operation = operation;
    }
}
