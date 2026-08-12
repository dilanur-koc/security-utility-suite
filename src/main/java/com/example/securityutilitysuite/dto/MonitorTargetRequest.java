package com.example.securityutilitysuite.dto;

import com.example.securityutilitysuite.enums.MonitorType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * POST /api/v1/monitor istek govdesi.
 */
public record MonitorTargetRequest(

        @NotBlank(message = "hedef boş olamaz")
        @Size(max = 500, message = "hedef en fazla 500 karakter olabilir")
        String target,

        @NotNull(message = "izleme türü belirtilmeli")
        MonitorType type
) {
}
