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

import java.util.Collection;
import java.util.List;

/**
 * Classe de entidade de usuário
 *
 * Necessariamente precisa da implementação de UserDetails
 * para que o Spring Security possa fazer a utilização dessa
 * entidade como usuário para autenticação
 */
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

    /**
     * Utilizado para retornar as formas de autoridade do usuário
     *
     * Obrigatoriamente deve implementar esse método para o Spring Security
     * possa utilizar
     *
     * @return autoridades
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(this.perfil);
    }

    /**
     * Utilizado para retornar a senha do usuário
     *
     * Obrigatoriamente deve implementar esse método para o Spring Security
     * possa utilizar
     *
     * @return senha
     */
    @Override
    public String getPassword() {
        return this.senha;
    }

    /**
     * Utilizado para retornar o usuário usado para autenticação (e.g. email)
     *
     * Obrigatoriamente deve implementar esse método para o Spring Security
     * possa utilizar
     *
     * @return usuario
     */
    @Override
    public String getUsername() {
        return this.usuario;
    }

}
