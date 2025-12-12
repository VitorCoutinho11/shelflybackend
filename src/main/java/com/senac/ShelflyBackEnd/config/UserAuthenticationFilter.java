package com.senac.ShelflyBackEnd.config;

import com.senac.ShelflyBackEnd.entity.Usuario;
import com.senac.ShelflyBackEnd.repository.UsuarioRepository;
import com.senac.ShelflyBackEnd.service.JwtTokenService;
import com.senac.ShelflyBackEnd.service.UsuarioDetailsImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class UserAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenService jwtTokenService;
    private final UsuarioRepository usuarioRoleRepository;

    // CHAVE SECRETA: DEVE SER A MESMA USADA NO JwtTokenService
    private static final String SECRET_KEY = "4Z^XrroxR@dWxqf$mTTKwW$!@#qGr4P";
    private static final String ISSUER = "pizzurg-api";

    public UserAuthenticationFilter(JwtTokenService jwtTokenService, UsuarioRepository usuarioRoleRepository) {
        this.jwtTokenService = jwtTokenService;
        this.usuarioRoleRepository = usuarioRoleRepository;
    }

    // 🚨 MODIFICAÇÃO CRUCIAL: Este método define quais rotas o filtro JWT deve IGNORAR.
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();

        // 1. OPTIONS SEMPRE liberado
        if (request.getMethod().equals(HttpMethod.OPTIONS.name())) {
            return true;
        }

        // 2. ROTAS PÚBLICAS: Incluir a rota de Gêneros aqui
        String[] publicPaths = {
                // Rotas de Usuário (Login/Cadastro)
                "/shelfly/users/login",
                "/shelfly/users",
                "/users/login",
                "/users",

                // Rotas de Sistema
                "/h2-console",
                "/v3/api-docs",
                "/swagger-ui",

                "/api/genero/listar",
                "/shelfly/api/genero/listar"
        };

        for (String publicPath : publicPaths) {
            if (path.equals(publicPath) || path.startsWith(publicPath + "/")) {
                return true;
            }
        }

        // Se não for nenhuma rota pública, o filtro DEVE ser executado
        return false;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // Este bloco só será executado se shouldNotFilter retornar FALSE.

        String token = recoveryToken(request);

        // 2. Se o token existir, tenta autenticar
        if (token != null) {

            try {
                Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);

                // 1. Verifica e Obtém o Assunto (E-mail)
                String subject = JWT.require(algorithm)
                        .withIssuer(ISSUER)
                        .build()
                        .verify(token)
                        .getSubject();

                // 2. EXTRAIR AS ROLES DO PAYLOAD
                List<String> rolesFromToken = JWT.require(algorithm)
                        .withIssuer(ISSUER)
                        .build()
                        .verify(token)
                        .getClaim("roles") // <<<<< LENDO A CLAIM 'roles'
                        .asList(String.class);


                // 3. Autentica se o usuário e as roles forem válidos
                if (usuarioRoleRepository.findByEmail(subject).isPresent() && rolesFromToken != null) {

                    // Mapeia as Strings das Roles (Ex: "ROLE_ADMIN") para objetos GrantedAuthority
                    List<GrantedAuthority> authorities = rolesFromToken.stream()
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());

                    // Cria o objeto de autenticação com as autoridades
                    Authentication authentication =
                            new UsernamePasswordAuthenticationToken(subject, null, authorities);

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }

            } catch (JWTVerificationException exception){
                // Se o token for inválido/expirado, o Spring Security bloqueará a requisição mais adiante.
                System.out.println("Token inválido ou expirado. Requisição não autenticada no contexto.");
            }
        }

        filterChain.doFilter(request, response); // Continua o processamento
    }

    // Recupera o token do cabeçalho Authorization da requisição
    private String recoveryToken(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null) {
            return authorizationHeader.replace("Bearer ", "");
        }
        return null;
    }
}