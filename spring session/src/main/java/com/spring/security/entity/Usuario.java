package com.spring.security.entity;

import com.spring.security.enums.Perfil;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Usuario implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String usuario;

    private String senha;

    private Perfil perfil;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        ArrayList<Perfil> perfis = new ArrayList<>();
        perfis.add(Perfil.USUARIO);

        if (this.perfil != Perfil.USUARIO) {
            perfis.add(Perfil.FUNCIONARIO);
        }

        if (this.perfil == Perfil.ADMINISTRADOR) {
            perfis.add(Perfil.ADMINISTRADOR);
        }

        return perfis;
    }

    @Override
    public String getPassword() {
        return this.senha;
    }

    @Override
    public String getUsername() {
        return this.usuario;
    }
}
