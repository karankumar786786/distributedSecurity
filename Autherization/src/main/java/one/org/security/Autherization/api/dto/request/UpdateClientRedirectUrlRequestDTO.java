package one.org.security.Autherization.api.dto.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;

public record UpdateClientRedirectUrlRequestDTO(
        @NotEmpty(message = "client id cannot be blank") String clientId,
        @NotEmpty(message = "redirectUrl cannot be empty") @Pattern(regexp = "^(https://|http://localhost).*", message = "Redirect URI must use HTTPS (or http://localhost)") String redirectUrl) {

}
