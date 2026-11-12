package com.scrt.identity.web;

import com.scrt.identity.domain.AppUser;
import com.scrt.identity.repository.AppUserRepository;
import com.scrt.identity.web.dto.MeResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/me")
@RequiredArgsConstructor
public class MeController {

    private final AppUserRepository users;

    @GetMapping
    public MeResponse me(@AuthenticationPrincipal Jwt jwt) {
        UUID id = UUID.fromString(jwt.getClaimAsString("uid"));
        AppUser user = users.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        List<String> authorities = jwt.getClaimAsStringList("authorities");
        return new MeResponse(user.getId(), user.getEmail(), user.getDisplayName(), authorities);
    }
}