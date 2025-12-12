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
            "/users"
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
                        .requestMatchers("/h2-console/**").permitAll()

                        // 2. PRIORIDADE ALTA: ROTAS PÚBLICAS DE AUTENTICAÇÃO (POST)
                        .requestMatchers(HttpMethod.POST, "/users/login", "/users").permitAll()

                        // 3. OUTRAS ROTAS PÚBLICAS (GETs/Swagger)
                        .requestMatchers(ENDPOINTS_PUBLIC_GET).permitAll()

                        // ⭐️ CORREÇÃO FINAL GÊNEROS: MOVE OS GETS PÚBLICOS PARA CIMA
                        // Libera GET para Gêneros e Livros (Acesso anônimo a dados de catálogo)
                        .requestMatchers(HttpMethod.GET, "/api/genero/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/livro", "/api/livro/**").permitAll()

                        // 4. ADMIN LEVEL: Rotas restritas ao ADMIN
                        .requestMatchers("/admin/**").hasRole(ROLE_ADMIN)

                        // ----------------------------------------------------
                        // 5. CORREÇÃO DE GRANULARIDADE (USUARIO LEVEL)
                        // ----------------------------------------------------

                        // ** REGRAS DE GÊNEROS (Criação/Atualização/Exclusão) **
                        .requestMatchers(HttpMethod.POST, "/api/genero/criar").hasRole(ROLE_USUARIO)
                        .requestMatchers(HttpMethod.PUT, "/api/genero/atualizar/**").hasRole(ROLE_USUARIO)
                        .requestMatchers(HttpMethod.DELETE, "/api/genero/apagar/**").hasRole(ROLE_USUARIO)

                        // Rotas de Livro: Apenas a criação/atualização/deleção exigem USUARIO
                        .requestMatchers(HttpMethod.POST, "/api/livro/**").hasRole(ROLE_USUARIO) // CRIAÇÃO
                        .requestMatchers(HttpMethod.PUT, "/api/livro/**").hasRole(ROLE_USUARIO) // ATUALIZAÇÃO
                        .requestMatchers(HttpMethod.DELETE, "/api/livro/**").hasRole(ROLE_USUARIO) // EXCLUSÃO

                        // Rotas de Avaliação e Marcação: TUDO exige USUARIO (ajuste se a regra for diferente)
                        .requestMatchers("/api/avaliacao/**").hasRole(ROLE_USUARIO)
                        .requestMatchers("/api/marcacao/**").hasRole(ROLE_USUARIO)


                        // 6. BLOQUEIO PADRÃO: Qualquer outra requisição DEVE ser autenticada (token válido)
                        .anyRequest().authenticated()
                )

                // 7. Adiciona o filtro JWT antes do tratamento de requisição
                .addFilterBefore(userAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

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