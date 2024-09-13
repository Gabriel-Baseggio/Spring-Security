package com.spring.security.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

@AllArgsConstructor
public enum Perfil implements GrantedAuthority {
    ADMIN("Administrador"),
    USUARIO("Usuário");

    private final String nome;

    @Override
    public String getAuthority() {
        return this.name();
    }
}
