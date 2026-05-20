package com.application.authentication.service;

import com.application.authentication.model.Users;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

@NoArgsConstructor
@Getter
@Setter

public class UserDetailImpl implements UserDetails {

    @Serial
    private static final long serialVersionUID = 1L;

    private String userId;
    private String username;
    private String email;

    @JsonIgnore
    private String password;

    private boolean is2faEnabled;

    private Collection<? extends GrantedAuthority> authorities;

    public UserDetailImpl(String userId, String username, String email, String password,
                           boolean is2faEnabled, Collection<? extends GrantedAuthority> authorities) {
        this.userId = userId;
        this.username = username;
        this.email = email;
        this.password = password;
        this.is2faEnabled = is2faEnabled;
        this.authorities = authorities;
    }

    public static UserDetailImpl build(Users user) {
        List<SimpleGrantedAuthority> authorities =
                (user.getRoles() == null || user.getRoles().isEmpty())
                        ? List.of(new SimpleGrantedAuthority("ROLE_CUSTOMER"))
                        : user.getRoles().stream()
                        .map(r -> {
                            String role = r.getRoleType();           // e.g. "Admin"
                            role = role.toUpperCase();              // "ADMIN"
                            if (!role.startsWith("ROLE_")) role = "ROLE_" + role; // "ROLE_ADMIN"
                            return new SimpleGrantedAuthority(role);
                        })
                        .toList();

        return new UserDetailImpl(
                user.getUserId(),
                user.getUsername(),
                user.getEmail(),
                user.getPassword(),
                user.isTwoFactorEnabled(),
                authorities
        );
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserDetailImpl user = (UserDetailImpl) o;
        return Objects.equals(userId, user.userId);
    }

}

