package com.spring.security.security.utils;

import com.auth0.jwt.JWT;
import com.spring.security.entity.Usuario;
import jakarta.servlet.http.Cookie;
import org.springframework.stereotype.Component;

@Component
public class CookieUtils {

    public Cookie criarCookie(String jwt) {
        Cookie cookie = cookieDefault("USERTOKEN", jwt);
        cookie.setMaxAge(3600);
        return cookie;
    }

    public Cookie removerCookie() {
        return cookieDefault("USERTOKEN", "");
    }

    private static Cookie cookieDefault(String name, String value) {
        Cookie cookie = new Cookie(name, value);
        cookie.setMaxAge(0);
        cookie.setPath("/");
        cookie.setSecure(false);
        cookie.setHttpOnly(true);
        cookie.setDomain("localhost");
        return cookie;
    }
}
