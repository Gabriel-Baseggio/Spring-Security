package com.spring.security.security.controller;

import com.spring.security.entity.Usuario;
import com.spring.security.enums.Perfil;
import com.spring.security.security.controller.dto.LoginDTO;
import com.spring.security.security.service.AutenticacaoService;
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

@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
@CrossOrigin("*")
public class AutenticacaoController {

    private AuthenticationProvider authenticationProvider;

    private JwtUtils jwtUtils;

    private CookieUtils cookieUtils;

    private AutenticacaoService service;

    @PreAuthorize("permitAll()")
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginDTO loginDTO, HttpServletResponse response) {
        Authentication auth = new UsernamePasswordAuthenticationToken(loginDTO.usuario(), loginDTO.senha());

        auth = authenticationProvider.authenticate(auth);

        if (auth.isAuthenticated()) {
            Usuario usuario = (Usuario) auth.getPrincipal();
            String jwt = jwtUtils.criarToken(usuario);
            Cookie cookieJwt = cookieUtils.criarCookie(jwt);
            response.addCookie(cookieJwt);
        }

        return new ResponseEntity<>(auth.getPrincipal(), HttpStatus.OK);
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        service.logout(response);
        return new ResponseEntity<>(HttpStatus.OK);
    }

}