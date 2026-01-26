package one.org.security;

import jakarta.validation.constraints.NotBlank;

public record HmacDTO(
                @NotBlank(message = "signature cant blank") String signature,
                @NotBlank(message = "signature cannt be blank") String message,
                @NotBlank(message = "keyId cannot be null") String keyId,
                String providedSignature) {
}
