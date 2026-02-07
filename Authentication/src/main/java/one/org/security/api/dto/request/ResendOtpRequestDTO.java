package one.org.security.api.dto.request;

import one.org.security.api.dto.enums.CheckUserExistRequestAvailableEnum;

public record ResendOtpRequestDTO(
                @jakarta.validation.constraints.NotNull(message = "purpose cannot be null") CheckUserExistRequestAvailableEnum purpose) {

}
