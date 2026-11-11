package com.scrt.identity.web.dto;

import com.scrt.identity.domain.AppUser;

import java.util.UUID;

public record UserResponse(UUID id, String email, String displayName) {

    public static UserResponse from(AppUser user) {
        return new UserResponse(user.getId(), user.getEmail(), user.getDisplayName());
    }
}