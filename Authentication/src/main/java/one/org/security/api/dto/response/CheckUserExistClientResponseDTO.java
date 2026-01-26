package one.org.security.api.dto.response;

import java.util.Map;

import jakarta.validation.constraints.NotBlank;

public record CheckUserExistClientResponseDTO(
    @NotBlank
        boolean exist,
        Map<String, Boolean> data
) {
    
}
