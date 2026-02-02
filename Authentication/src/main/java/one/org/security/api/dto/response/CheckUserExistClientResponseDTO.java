package one.org.security.api.dto.response;

import java.util.Map;

import jakarta.validation.constraints.NotBlank;

public record CheckUserExistClientResponseDTO(
        @NotBlank boolean exist,
        Map<String, Boolean> data,
        String initToken) {
    // Constructor for backward compatibility
    public CheckUserExistClientResponseDTO(boolean exist, Map<String, Boolean> data) {
        this(exist, data, null);
    }
}
