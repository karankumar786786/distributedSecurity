package one.org.security.core.domain.dto;

import java.util.Map;

import jakarta.validation.constraints.NotBlank;
import one.org.security.core.domain.enums.CheckUserExistRequestAvailableEnum;

public record TempTokenDTO(
        @NotBlank(message = "this is for subject name etc") String subject,
        Map<String, Boolean> data,
        CheckUserExistRequestAvailableEnum reason) {
}
