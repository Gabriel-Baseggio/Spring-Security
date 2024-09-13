package com.spring.security.security.config;

import com.spring.security.security.service.AutenticacaoService;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;


@Configuration
@EnableMethodSecurity
@AllArgsConstructor
public class SecurityConfig {

    private final JwtFilter jwtFilter;

    /**
     * Bean para a repository de autenticação
     *
     * Instância de HttpSessionSecurityContextRepository
     */
    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    /**
     * Bean de filterChain definindo métodos necessários no filtro
     *
     * Precisa de um HttpSecurity
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity config) throws Exception {
        config
                // Define a repository com os contextos de autenticação
                // .securityContext(c -> securityContextRepository())
                // Desativa a tela de formulário padrão na request de login so Security
                .formLogin(AbstractHttpConfigurer::disable)
                // Desativa a tela de logout padrão do Security
                .logout(AbstractHttpConfigurer::disable)
                // Desativa o Cross Site Request Forgery
                .csrf(AbstractHttpConfigurer::disable)
                // Define a configuração de sessões como stateless (JWT)
                .sessionManagement(c -> c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .cors(c -> c.configurationSource(corsConfigurationSource()));
        // Define as autorizações para cada request
//                .authorizeHttpRequests(http -> {
//                    http
//                            .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
//                            .requestMatchers(HttpMethod.GET, "/auth/user").hasAuthority(Perfil.ADMIN.getAuthority())
//                            .anyRequest().authenticated();
//                });
        return config.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:3000", "http://localhost:4200"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE"));
        config.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    /**
     * Bean para o provedor de autenticação
     *
     * Instância de DaoAuthenticationProvider, setando a service de autenticação criada por nós e
     * o encoder de senha
     */
    @Bean
    public AuthenticationProvider authenticationProvider(AutenticacaoService autenticacaoService) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(autenticacaoService);
        authenticationProvider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
        return authenticationProvider;
    }

//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return NoOpPasswordEncoder.getInstance();
//        return new BCryptPasswordEncoder();
//    }

//    @Bean
//    public UserDetailsService authenticationService() {
//        List<Usuario> usuarios = repository.findAll();
//        List<UserDetails> userDetails = new ArrayList<>(usuarios);
//        return new InMemoryUserDetailsManager(userDetails);
//    }

}

