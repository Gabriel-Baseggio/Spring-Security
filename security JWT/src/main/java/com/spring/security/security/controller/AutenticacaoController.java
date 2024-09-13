package com.spring.security.security.controller;

import com.spring.security.entity.Usuario;
import com.spring.security.enums.Perfil;
import com.spring.security.security.controller.dto.LoginDTO;
import com.spring.security.security.utils.CookieUtils;
import com.spring.security.security.utils.JwtUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.*;

/**
 * Controller de autenticação
 *
 * Controller para fazer o endpoint de login
 */
@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
@CrossOrigin("*")
public class AutenticacaoController {

    /**
     * Injeção necessária para fazer a autenticação usando o provider correta
     */
    private AuthenticationProvider authenticationProvider;

    /**
     * Injeção necessária para salvar a sessão de login do usuário na repository
     */
    private SecurityContextRepository securityContextRepository;

    private JwtUtils jwtUtils;

    private CookieUtils cookieUtils;

    /**
     * Endpoint de login
     *
     * @param loginDTO DTO de login
     * @param response resposta
     * @return usuário autenticado
     */
    @PreAuthorize("permitAll()")
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginDTO loginDTO, HttpServletResponse response) {

        // Classe de autenticação do Spring Security, instanciado pelo UsernamePasswordAuthenticationToken
        // que recebe o usuário e senha apenas, setando assim um usuário não autenticado
        Authentication auth = new UsernamePasswordAuthenticationToken(loginDTO.usuario(), loginDTO.senha());

        // Faz a autenticação do usuário e salva o retorno (usuário autenticado)
        // na mesma variável auth
        auth = authenticationProvider.authenticate(auth);

        // Se o usuário estiver autenticado (fez login corretamente),
        // salva a sessão de login do usuário
        if (auth.isAuthenticated()) {
            Usuario usuario = (Usuario) auth.getPrincipal();

            String jwt = jwtUtils.criarToken(usuario);

            Cookie cookieJwt = cookieUtils.criarCookie(jwt);

            response.addCookie(cookieJwt);

            // Cria um contexto de segurança vazio
            // SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            // Seta a autenticação no contexto de segurança
            // securityContext.setAuthentication(auth);
            // Salva o contexto de segurança na repository (obrigatoriamente precisa de uma HttpRequest e
            // uma HttpResponse
            // securityContextRepository.saveContext(securityContext, request, response);
        }

        return new ResponseEntity<>(auth.getPrincipal(), HttpStatus.OK);
    }

    @PreAuthorize("hasAuthority('USUARIO')")
    @GetMapping("/user")
    public ResponseEntity<?> usuarioLogado(@AuthenticationPrincipal Usuario usuario) {
        return new ResponseEntity<>(usuario, HttpStatus.OK);
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        Cookie cookie = cookieUtils.removerCookie();
        response.addCookie(cookie);
        return new ResponseEntity<>(HttpStatus.OK);
    }

}