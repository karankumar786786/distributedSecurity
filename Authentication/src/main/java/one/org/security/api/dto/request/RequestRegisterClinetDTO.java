package one.org.security.api.dto.request;

import java.util.List;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

public record RequestRegisterClinetDTO(
        @NotBlank(message = "client id cannot be blank") String clientId,
        @NotBlank(message = "redirect url cannot be blank") String redirectUrl,
        @NotEmpty(message = "scopes cannot be blank") List<String> scopes) {

}
