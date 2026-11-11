package com.scrt.identity.service;

import com.scrt.identity.domain.AppUser;
import com.scrt.identity.repository.AppUserRepository;
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

    @Transactional
    public AppUser register(String email, String rawPassword, String displayName) {
        String normalized = email.trim().toLowerCase();
        if (users.existsByEmailIgnoreCase(normalized)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already registered");
        }
        AppUser user = new AppUser();
        user.setEmail(normalized);
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.setDisplayName(displayName);
        return users.save(user);
    }
}