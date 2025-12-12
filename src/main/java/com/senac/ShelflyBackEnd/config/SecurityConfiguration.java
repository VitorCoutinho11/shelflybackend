package com.senac.ShelflyBackEnd.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    @Autowired
    private UserAuthenticationFilter userAuthenticationFilter;

    // --- Definição das Roles Simplificadas (Sem prefixo ROLE_ aqui) ---
    public static final String ROLE_USUARIO = "USUARIO";
    public static final String ROLE_ADMIN = "ADMIN";

    // --- ENDPOINTS PÚBLICOS ---
    public static final String [] ENDPOINTS_PUBLIC_GET = {
            "/home",
            "/index.html",
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/users" // GET para listagem/informação pública de usuários (se existir)
    };

    // --- ENDPOINTS COM ACESSO RESTRITO POR ROLE ---
    // Manter a ordem aqui é menos crítico do que no 'authorizeHttpRequests'
    public static final String [] ENDPOINTS_USUARIO_LEVEL = {
            "/api/avaliacao/**",
            "/api/livro/**",
            "/api/marcacao/**",
    };


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 1. Desabilita CSRF
                .csrf(csrf -> csrf.disable())

                // 2. Configura Sessão Stateless (JWT)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // 3. Libera Frame Options para H2 Console (CRÍTICO)
                .headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()))

                .authorizeHttpRequests(auth -> auth
                        // 1. PRIORIDADE MÁXIMA: OPTIONS (CORS Pre-flight) e H2
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers("/h2-console/**").permitAll() // CRÍTICO: Libera H2 completo

                        // 2. PRIORIDADE ALTA: ROTAS PÚBLICAS DE AUTENTICAÇÃO (POST)
                        // Garante que o Login/Cadastro sejam liberados antes de tudo
                        .requestMatchers(HttpMethod.POST, "/users/login", "/users").permitAll()

                        // 3. OUTRAS ROTAS PÚBLICAS (GETs/Swagger)
                        .requestMatchers(ENDPOINTS_PUBLIC_GET).permitAll()

                        // 4. ADMIN LEVEL: Rotas restritas ao ADMIN (Mais ampla)
                        // Usa hasRole para que o Spring adicione o prefixo ROLE_
                        .requestMatchers("/admin/**").hasRole(ROLE_ADMIN)

                        // 5. USUARIO LEVEL: Rotas restritas ao USUARIO
                        // Usa hasRole. O ADMIN já pode ter acesso implícito ou explícito aqui dependendo da sua arquitetura.
                        .requestMatchers(ENDPOINTS_USUARIO_LEVEL).hasRole(ROLE_USUARIO)

                        // 6. BLOQUEIO PADRÃO: Qualquer outra requisição deve ser autenticada (Token válido)
                        // Apenas exige um token válido, sem checar a role específica
                        .anyRequest().authenticated()
                )

                // 7. Adiciona o filtro JWT antes do tratamento de requisição
                .addFilterBefore(userAuthenticationFilter, UsernamePasswordAuthenticationFilter.class); // <-- MELHOR LOCAL

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}