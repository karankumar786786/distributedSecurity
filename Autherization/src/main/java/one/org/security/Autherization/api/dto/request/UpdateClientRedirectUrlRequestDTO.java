package one.org.security.Autherization.api.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record UpdateClientRedirectUrlRequestDTO(
                @NotBlank(message = "client id cannot be blank") String clientId,

                @NotBlank(message = "redirectUrl cannot be empty") @Pattern(regexp = "^(https://|http://localhost|http://127\\.0\\.0\\.1).*", message = "Redirect URL must use HTTPS or be localhost") String redirectUrl) {

}
