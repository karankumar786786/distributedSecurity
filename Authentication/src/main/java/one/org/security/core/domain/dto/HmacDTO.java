package one.org.security.core.domain.dto;

import jakarta.validation.constraints.NotBlank;

public record HmacDTO(
        @NotBlank(message = "signature cant blank") String signature,
        @NotBlank(message = "signature cannt be blank") String message,
        @NotBlank(message = "keyId cannot be null") String keyId,
        // @NotBlank(groups = ) TODO from the filture class i should bind to provide
        // this
        String providedSignature) {
}
