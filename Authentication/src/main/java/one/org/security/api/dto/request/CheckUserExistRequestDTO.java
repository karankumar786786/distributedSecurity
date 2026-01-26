package one.org.security.api.dto.request;

import jakarta.validation.constraints.NotNull;
import one.org.security.api.dto.enums.CheckUserExistRequestAvailableEnum;
import jakarta.validation.constraints.NotBlank;

public record CheckUserExistRequestDTO(
        @NotBlank String username,
        @NotNull CheckUserExistRequestAvailableEnum reason) {

}
