package one.org.security.api.dto.request;

import jakarta.validation.constraints.NotNull;
import one.org.security.api.dto.enums.ForgetPasswordRequestEnum;

public record ForgetPasswordRequestDTO(
                @NotNull ForgetPasswordRequestEnum option,
                @jakarta.validation.constraints.NotBlank(message = "loginId cannot be null") String loginId) {
}
