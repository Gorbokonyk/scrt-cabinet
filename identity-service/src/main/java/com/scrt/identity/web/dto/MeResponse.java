package com.scrt.identity.web.dto;

import java.util.List;
import java.util.UUID;

public record MeResponse(UUID id, String email, String displayName, List<String> authorities) {
}