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

    // --- Definição das Roles Simplificadas ---
    public static final String ROLE_USUARIO = "USUARIO";
    public static final String ROLE_ADMIN = "ADMIN"; // A role mais alta

    // --- ENDPOINTS PÚBLICOS ---
    public static final String [] ENDPOINTS_WITH_AUTHENTICATION_NOT_REQUIRED = {
            "/h2-console",
            "/",
            "/index.html",
            // 🔓 Swagger/OpenAPI UI
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/users",
            "/users/login"
    };

    // --- ENDPOINTS COM ACESSO RESTRITO POR ROLE ---

    // 1. ENDPOINTS para ROLE_USUARIO

    public static final String [] ENDPOINTS_USUARIO_LEVEL = {
            // Inclui permissão para criar livros, marcações e avaliações (POST/GET/PUT/DELETE nos próprios)
            "/api/avaliacao/criar",
            "/api/avaliacao/atualizar/{avaliacaoId}",
            "/api/avaliacao/apagar/{avaliacaoId}",
            "/api/livro/criar",
            "/api/livro/atualizar/{livroId}",
            "/api/livro/apagar/{livroId}",
            "/api/marcacao/criar",
            "/api/marcacao/apagar/{marcacaoId}",
            "/api/marcacao/atualizar/{marcacaoId}",

    };



    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // 1. Permissões públicas (NÃO REQUER AUTENTICAÇÃO)
                        .requestMatchers(ENDPOINTS_WITH_AUTHENTICATION_NOT_REQUIRED).permitAll()
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // 2. Permissões Específicas:

                        // USUARIO LEVEL: Acessível por ROLE_USUARIO E ROLE_ADMIN
                        // Uso de hasAnyRole para conceder acesso cumulativo ao ADMIN
                        .requestMatchers(ENDPOINTS_USUARIO_LEVEL).hasAnyRole(ROLE_USUARIO, ROLE_ADMIN)

                        // 3. Permissão Curinga para ROLE_ADMIN:
                        // Qualquer outra rota na API ("/**") exige ROLE_ADMIN.
                        // Esta regra deve vir antes do denyAll().
                        .requestMatchers("/**").hasRole(ROLE_ADMIN)

                        // 4. Bloqueio padrão (qualquer outra requisição é negada)
                        .anyRequest().denyAll()
                )
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