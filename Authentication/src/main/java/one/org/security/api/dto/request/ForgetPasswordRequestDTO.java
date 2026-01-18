package one.org.security.api.dto.request;

import jakarta.validation.constraints.NotNull;
import one.org.security.core.domain.enums.ForgetPasswordRequestEnum;

public record ForgetPasswordRequestDTO(
        @NotNull ForgetPasswordRequestEnum option) {
}
