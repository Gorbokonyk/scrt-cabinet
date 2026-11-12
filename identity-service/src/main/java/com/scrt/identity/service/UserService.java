package com.scrt.identity.service;

import com.scrt.identity.domain.AppUser;
import com.scrt.identity.domain.Application;
import com.scrt.identity.domain.Role;
import com.scrt.identity.repository.AppUserRepository;
import com.scrt.identity.repository.ApplicationRepository;
import com.scrt.identity.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class UserService {

    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final ApplicationRepository applications;
    private final RoleRepository roles;

    private static final String DEFAULT_CLIENT = "scrt-bff";
    private static final String DEFAULT_ROLE = "USER";

    @Transactional
    public AppUser register(String email, String rawPassword, String displayName) {
        String normalized = email.trim().toLowerCase();
        if (users.existsByEmailIgnoreCase(normalized)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already registered");
        }
        AppUser user = new AppUser();

        Application app = applications.findByClientId(DEFAULT_CLIENT)
                .orElseThrow(() -> new IllegalStateException("Application not seeded: " + DEFAULT_CLIENT));
        Role role = roles.findByApplicationIdAndCode(app.getId(), DEFAULT_ROLE)
                .orElseThrow(() -> new IllegalStateException("Role not seeded: " + DEFAULT_ROLE));
        user.getRoles().add(role);

        user.setEmail(normalized);
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.setDisplayName(displayName);
        return users.save(user);
    }
}