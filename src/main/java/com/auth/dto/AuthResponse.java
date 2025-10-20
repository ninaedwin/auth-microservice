package com.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * DTO para response de autenticación
 */
public record AuthResponse(
        @JsonProperty("access_token")
        String accessToken,

        @JsonProperty("token_type")
        String tokenType,

        @JsonProperty("expires_in")
        Long expiresIn,

        @JsonProperty("refresh_token")
        String refreshToken,

        @JsonProperty("scope")
        String scope
) {
}
