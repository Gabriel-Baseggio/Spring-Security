package com.spring.security.security.service;

import com.spring.security.entity.Usuario;
import com.spring.security.repository.UsuarioRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@AllArgsConstructor
public class AutenticacaoService implements UserDetailsService {

    private UsuarioRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return buscarUsuarioPorUsername(username);
    }

    private Usuario buscarUsuarioPorUsername(String username) {
        Optional<Usuario> usuario = repository.findByUsuario(username);

        if (username.isEmpty()) {
            throw new UsernameNotFoundException("Credenciais inválidas");
        }

        return usuario.get();
    }

    public void logout(SecurityContextRepository securityContextRepository, HttpServletRequest req,
                       HttpServletResponse res) {
        SecurityContext empty = SecurityContextHolder.createEmptyContext();
        securityContextRepository.saveContext(empty, req, res);
        Cookie[] cookies = req.getCookies();
        for (Cookie c : cookies) {
            if (c.getName().equals("JSESSIONID")) {
                c.setMaxAge(0);
                c.setPath("/");
                res.addCookie(c);
                break;
            }
        }
    }
}
