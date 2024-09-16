package com.spring.security.security.service;

import com.spring.security.entity.Usuario;
import com.spring.security.repository.UsuarioRepository;
import com.spring.security.security.utils.CookieUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@AllArgsConstructor
public class AutenticacaoService implements UserDetailsService {

    private UsuarioRepository repository;

    private CookieUtils cookieUtils;

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
        return repository.findByEmail(email);
    }

    public void logout(HttpServletResponse response) {
        Cookie cookie = cookieUtils.removerCookie();
        response.addCookie(cookie);
    }
}
