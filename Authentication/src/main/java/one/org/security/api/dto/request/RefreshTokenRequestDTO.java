package one.org.security.api.dto.request;

import jakarta.validation.constraints.NotBlank;

public record RefreshTokenRequestDTO(
        @NotBlank(message = "Refresh token cannot be blank") String refreshToken) {
}
