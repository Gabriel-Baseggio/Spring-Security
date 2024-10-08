package com.spring.security.entity;

import com.spring.security.enums.Perfil;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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

    @Column(nullable = false)
    @NotBlank
    private String nome;

    @Column(unique = true, nullable = false)
    @NotBlank
    private String usuario;

    @Column(unique = true, nullable = false)
    @NotBlank
    private String email;

    @Column(nullable = false)
    @NotBlank
    private String senha;

    private Perfil perfil;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<Perfil> perfis = new ArrayList<>();
        perfis.add(Perfil.USUARIO);

        if (this.perfil != Perfil.USUARIO) {
            perfis.add(Perfil.FUNCIONARIO);
        }

        if (this.perfil == Perfil.ADMINISTRADOR) {
            perfis.add(this.perfil);
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
