package com.example.securityutilitysuite.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * POST /api/v1/encode istek govdesi.
 */
public class EncodeRequest {

    /** Islenecek metin. Ust sinir, kaza ile devasa govde gonderilmesini onler. */
    @NotBlank(message = "input boş olamaz")
    @Size(max = 100_000, message = "input en fazla 100.000 karakter olabilir")
    private String input;

    @NotNull(message = "format belirtilmeli")
    private Format format;

    @NotNull(message = "operation belirtilmeli")
    private Operation operation;

    public enum Format {
        BASE64,
        BASE64URL,
        HEX
    }

    public enum Operation {
        ENCODE,
        DECODE
    }

    public EncodeRequest() {
    }

    public EncodeRequest(String input, Format format, Operation operation) {
        this.input = input;
        this.format = format;
        this.operation = operation;
    }

    public String getInput() {
        return input;
    }

    public void setInput(String input) {
        this.input = input;
    }

    public Format getFormat() {
        return format;
    }

    public void setFormat(Format format) {
        this.format = format;
    }

    public Operation getOperation() {
        return operation;
    }

    public void setOperation(Operation operation) {
        this.operation = operation;
    }
}
