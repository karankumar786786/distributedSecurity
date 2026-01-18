package one.org.security.core.domain.dto;

import jakarta.validation.constraints.NotBlank;

public record TokenHeaderDTO(
    @NotBlank(message = "from which service it is issued")
    String issuer,
    @NotBlank(message = "hmacKeyId is required")
    String hmackeyId,
    @NotBlank(message = "jwtKeyId is required")
    String jwtKeyId
) {}
