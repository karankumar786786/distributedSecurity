package one.org.security.api.dto.request;

import jakarta.validation.constraints.NotBlank;

public record VerifyLoginRequestDTO(
    @NotBlank(message = "username cannot be blank")
    String username,
    String password,
    boolean passwordLogin,
    boolean passkeyLogin,
    String challange
) {
    
}
