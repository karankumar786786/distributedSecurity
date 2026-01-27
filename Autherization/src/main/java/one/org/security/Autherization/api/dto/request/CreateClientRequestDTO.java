package one.org.security.Autherization.api.dto.request;

import jakarta.validation.constraints.NotEmpty;

public record CreateClientRequestDTO(
    @NotEmpty(message = "client id cannot be empty")
    String clientId,
    String redirectUrl
) {}
