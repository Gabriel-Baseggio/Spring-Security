package com.spring.security.security.controller;

import com.spring.security.entity.Usuario;
import com.spring.security.security.controller.dto.LoginDTO;
import com.spring.security.security.service.AutenticacaoService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
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
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;

@RestController
@AllArgsConstructor
@RequestMapping("/api/auth")
public class AutenticacaoController {

    private AuthenticationProvider authenticationProvider;

    private SecurityContextRepository securityContextRepository;

    private AutenticacaoService autenticacaoService;

    @PreAuthorize("permitAll()")
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginDTO loginDTO, HttpServletRequest req, HttpServletResponse res) {
        Authentication auth = new UsernamePasswordAuthenticationToken(loginDTO.usuario(), loginDTO.senha());
        auth = authenticationProvider.authenticate(auth);

        if (auth.isAuthenticated()) {
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(auth);
            securityContextRepository.saveContext(context, req, res);
        }

        return new ResponseEntity<>(auth.getPrincipal(), HttpStatus.OK);
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest req, HttpServletResponse res) {
        autenticacaoService.logout(securityContextRepository, req, res);
        return new ResponseEntity<>(HttpStatus.OK);
    }

}
