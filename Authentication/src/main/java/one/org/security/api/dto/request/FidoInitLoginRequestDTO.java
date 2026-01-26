package one.org.security.api.dto.request;

import jakarta.validation.constraints.NotBlank;

public record FidoInitLoginRequestDTO(
        @NotBlank(message = "loginId cannot be blank") String loginId) {
}
