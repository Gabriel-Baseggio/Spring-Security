package com.spring.security.security.config;

import com.spring.security.entity.Usuario;
import com.spring.security.security.utils.CookieUtils;
import com.spring.security.security.utils.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

@Component
@AllArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private JwtUtils jwtUtils;

    private CookieUtils cookieUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String uri = request.getRequestURI();
        String method = request.getMethod();

        if (!isPublicEndpoint(uri, method)) {
            try {
                Cookie[] cookies = request.getCookies();
                Optional<Cookie> cookieOptional = Arrays.stream(cookies)
                        .filter(cookie -> cookie.getName().equals("USERTOKEN")).findFirst();
                if (cookieOptional.isPresent()) {
                    String token = cookieOptional.get().getValue();
                    Authentication authentication = jwtUtils.validarToken(token);
                    saveContext(authentication);
                    if (!uri.equals("/auth/logout")) {
                        revigorateToken(response, authentication);
                    }
                }
            } catch (Exception e) {
                response.setStatus(401);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private void saveContext(Authentication authentication) {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
    }

    private void revigorateToken(HttpServletResponse response, Authentication authentication) {
        String novoToken = jwtUtils.criarToken((Usuario) authentication.getPrincipal());
        Cookie cookie = cookieUtils.criarCookie(novoToken);
        response.addCookie(cookie);
    }

    private boolean isPublicEndpoint(String uri, String method) {
        return uri.equals("/auth/login") && method.equals("POST");
    }

}
