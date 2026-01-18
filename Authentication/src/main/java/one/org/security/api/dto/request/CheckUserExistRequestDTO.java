package one.org.security.api.dto.request;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.NotBlank;
import one.org.security.core.domain.enums.CheckUserExistRequestAvailableEnum;

public record CheckUserExistRequestDTO(
                @NotBlank String username,
                @NotNull CheckUserExistRequestAvailableEnum reason
            ) {

}
