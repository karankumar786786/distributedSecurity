package one.org.security.Autherization.api.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record CreateClientRequestDTO(
        @NotBlank(message = "client id cannot be empty or whitespace") String clientId,

        @NotBlank(message = "redirect url cannot be null or whitespace") @Pattern(regexp = "^(https://|http://localhost|http://127\\.0\\.0\\.1).*", message = "Redirect URL must use HTTPS or be localhost") String redirectUrl,

        @NotNull(message = "personalDataAccess declaration cannot be undefined") Boolean personalDataAccess,
        @NotNull(message = "profile declaration cannot be undefined") Boolean profile,
        @NotNull(message = "write declaration cannot be undefined") Boolean write) {
}
