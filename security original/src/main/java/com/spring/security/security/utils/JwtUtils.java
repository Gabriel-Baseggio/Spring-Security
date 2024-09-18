package com.spring.security.security.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.spring.security.entity.Usuario;
import com.spring.security.security.service.AutenticacaoService;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Component
@RequiredArgsConstructor
public class JwtUtils {

    @Value("${security.secret:SenhaForteParaOProjetoTopCareDaMi73}")
    private String senha;

    @NonNull
    private AutenticacaoService autenticacaoService;

    public String criarToken(Usuario usuario) {
        Instant instanteAssinatura = Instant.now();
        Instant instanteExpiracao = instanteAssinatura.plus(1, ChronoUnit.HOURS);
        String[] authorities = usuario.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .toArray(String[]::new);

        String jwt = JWT.create()
                .withIssuer("Top Care")
                .withIssuedAt(instanteAssinatura)
                .withSubject(usuario.getUsuario())
                .withExpiresAt(instanteExpiracao)
                .withArrayClaim("authorities", authorities)
                .sign(algorithm());

        return jwt;
    }

    public Authentication validarToken(String token) {
        JWTVerifier verificador = JWT.require(algorithm()).build();
        DecodedJWT tokenVerificado = verificador.verify(token);
        String username = tokenVerificado.getSubject();
        Usuario usuario = (Usuario) autenticacaoService.loadUserByUsername(username);
        return new UsernamePasswordAuthenticationToken(usuario, usuario.getPassword(), usuario.getAuthorities());
    }

    public Algorithm algorithm() {
        return Algorithm.HMAC256(senha);
    }

}
