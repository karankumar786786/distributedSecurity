package one.org.security.Autherization.api.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record SecurityIntegrityKeyCreateRequest(
        @NotNull @NotBlank String key) {
}
