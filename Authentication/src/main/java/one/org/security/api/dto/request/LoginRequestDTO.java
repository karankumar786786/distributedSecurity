package one.org.security.api.dto.request;

import jakarta.validation.constraints.NotBlank;

public record LoginRequestDTO(
        @NotBlank(message = "credential cannot be null") String credential
) {
}
