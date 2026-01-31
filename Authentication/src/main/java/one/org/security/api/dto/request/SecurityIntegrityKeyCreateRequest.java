package one.org.security.api.dto.request;

import jakarta.validation.constraints.NotEmpty;

public record SecurityIntegrityKeyCreateRequest(
    @NotEmpty(message = "key cannot be null")
    String key
) {
    
}
