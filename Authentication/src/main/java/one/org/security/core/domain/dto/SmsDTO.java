package one.org.security.core.domain.dto;

import jakarta.validation.constraints.NotBlank;

public record SmsDTO(
    @NotBlank(message = "to cannot be blank")
    String to,
    @NotBlank(message = "message cannot be blank")
    String message
) {
    
}
