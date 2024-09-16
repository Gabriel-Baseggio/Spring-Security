package com.spring.security.enums;

import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@AllArgsConstructor
public enum Perfil implements GrantedAuthority {

    ADMINISTRADOR("Administrador"),
    FUNCIONARIO("Funcionario"),
    USUARIO("Usuario");

    private final String nome;


    @Override
    public String getAuthority() {
        return this.name();
    }
}
