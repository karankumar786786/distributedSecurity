package one.org.security.core.domain.dto;

import jakarta.validation.constraints.NotBlank;

public record MailDTO(
    @NotBlank(message = "to cannot be null")
    String to,
    @NotBlank(message = "subject cannt be null")
    String subject,
    @NotBlank(message = "body cannot be null")
    String body
) {
    
}
