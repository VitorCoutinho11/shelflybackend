package com.senac.ShelflyBackEnd.service;

import com.senac.ShelflyBackEnd.entity.Usuario;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;

public class UsuarioDetailsImpl implements UserDetails {
    private Usuario usuarioRole; // Classe de usuário que criamos anteriormente

    public UsuarioDetailsImpl(Usuario usuarioRole) {
        this.usuarioRole = usuarioRole;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 🚨 CORREÇÃO: REMOVER A ADIÇÃO MANUAL DO PREFIXO "ROLE_"
        // Pois o role.getName().name() JÁ ESTÁ RETORNANDO "ROLE_ADMIN".
        return usuarioRole.getRoles()
                .stream()
                // Apenas usa o nome exato que está vindo da sua Entity/Enum (que já tem ROLE_).
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return usuarioRole.getSenha();
    } // Retorna a credencial do usuário que criamos anteriormente

    @Override
    public String getUsername() {
        return usuarioRole.getEmail();
    } // Retorna o nome de usuário do usuário que criamos anteriormente

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
