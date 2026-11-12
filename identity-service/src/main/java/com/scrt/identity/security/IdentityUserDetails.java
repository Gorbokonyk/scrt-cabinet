package com.scrt.identity.security;

import com.scrt.identity.domain.AppUser;
import com.scrt.identity.domain.UserStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

public class IdentityUserDetails implements UserDetails {

    private final UUID id;
    private final String email;
    private final String passwordHash;
    private final boolean enabled;
    private final boolean nonLocked;
    private final Set<GrantedAuthority> authorities;

    public IdentityUserDetails(AppUser user) {
        this.id = user.getId();
        this.email = user.getEmail();
        this.passwordHash = user.getPasswordHash();
        this.enabled = user.getStatus() == UserStatus.ACTIVE;
        this.nonLocked = user.getLockedUntil() == null
                || user.getLockedUntil().isBefore(OffsetDateTime.now());

        Set<GrantedAuthority> result = new HashSet<>();
        user.getRoles().forEach(role -> {
            String client = role.getApplication().getClientId();
            result.add(new SimpleGrantedAuthority(client + ":ROLE_" + role.getCode()));
            role.getPermissions().forEach(p ->
                    result.add(new SimpleGrantedAuthority(client + ":" + p.getCode())));
        });
        this.authorities = result;
    }

    public UUID getId() {
        return id;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonLocked() {
        return nonLocked;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}