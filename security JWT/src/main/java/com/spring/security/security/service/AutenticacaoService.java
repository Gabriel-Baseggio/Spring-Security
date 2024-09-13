package com.spring.security.security.service;

import com.spring.security.entity.Usuario;
import com.spring.security.repository.UsuarioRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Service de autenticação
 *
 * Necessariamente precisa da implementação de UserDetailsService
 * para que o Spring Security possa fazer a utilização dessa
 * service para a busca de usuário para autenticação
 */
@Service
@AllArgsConstructor
public class AutenticacaoService implements UserDetailsService {

    private UsuarioRepository repository;

    /**
     * Método de busca de usuário por nome de usuário ou email
     *
     * Obrigatoriamente deve implementar esse método para o Spring Security
     * possa utilizar
     *
     * @param username nome de usuário ou email
     * @return usuário
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Usuario> usuario = buscarPorEmail(username);

        if (usuario.isEmpty()) {
            usuario = buscarPorUsuario(username);
        }

        if (usuario.isEmpty()) {
            throw new UsernameNotFoundException("Usuário não encontrado");
        }

        return usuario.get();
    }

    private Optional<Usuario> buscarPorUsuario(String usuario) {
        return repository.findByUsuario(usuario);
    }

    private Optional<Usuario> buscarPorEmail(String email) {
        if (!email.contains("@")) {
            return Optional.empty();
        }

        return repository.findByEmail(email);
    }

}
