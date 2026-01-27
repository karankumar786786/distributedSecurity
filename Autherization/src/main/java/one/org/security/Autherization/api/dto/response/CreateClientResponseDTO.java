package one.org.security.Autherization.api.dto.response;

import jakarta.validation.constraints.NotEmpty;

public record CreateClientResponseDTO(
    @NotEmpty(message="cleint id cannot be empty")
    String clientId,
    @NotEmpty(message = "client secret cannot be empty")
    String clientSecret
) {
    
}
