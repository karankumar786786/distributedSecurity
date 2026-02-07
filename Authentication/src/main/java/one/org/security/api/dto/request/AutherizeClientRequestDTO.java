package one.org.security.api.dto.request;

import jakarta.validation.constraints.NotBlank;

public record AutherizeClientRequestDTO(
        @NotBlank(message = "Client ID is required") String clientId) {

}
