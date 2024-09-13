package com.spring.security.security.controller.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginDTO(
        @NotBlank String usuario,
        @NotBlank String senha
) {
}
