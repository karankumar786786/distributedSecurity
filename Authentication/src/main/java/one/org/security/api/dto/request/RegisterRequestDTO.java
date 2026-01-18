package one.org.security.api.dto.request;

import jakarta.validation.constraints.NotBlank;

public record RegisterRequestDTO(
        @NotBlank(message = "Username cannot be blank") 
        String username,
        @NotBlank(message = "Password cannot be blank") 
        String password,
        String phoneNumber
    ) {

}
