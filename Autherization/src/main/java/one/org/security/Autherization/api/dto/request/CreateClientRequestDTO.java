package one.org.security.Autherization.api.dto.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record CreateClientRequestDTO(
        @NotEmpty(message = "client id cannot be empty") String clientId,
        @NotEmpty(message = "redirect url cannot be null") String redirectUrl,
        @NotNull(message = "personalDataAccess declaration cannot be undefined") Boolean personalDataAccess,
        @NotNull(message = "profile declaration cannot be undefined") Boolean profile,
        @NotNull(message = "write declaration cannot be undefined") Boolean write) {
}
