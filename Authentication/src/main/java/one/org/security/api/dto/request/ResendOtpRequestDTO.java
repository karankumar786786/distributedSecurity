package one.org.security.api.dto.request;

import jakarta.validation.constraints.NotBlank;
import one.org.security.api.dto.enums.CheckUserExistRequestAvailableEnum;

public record ResendOtpRequestDTO(
        @NotBlank(message = "purpose cannot be blank") CheckUserExistRequestAvailableEnum purpose) {

}
