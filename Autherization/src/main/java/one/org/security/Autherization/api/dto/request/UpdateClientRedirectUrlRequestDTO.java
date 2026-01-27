package one.org.security.Autherization.api.dto.request;

import jakarta.validation.constraints.NotEmpty;

public record UpdateClientRedirectUrlRequestDTO(
    @NotEmpty(message = "client id cannot be blank")
    String clientId,
    @NotEmpty(message = "redirectUrl cannot be empty")
    String redirectUrl
) {
    
}
