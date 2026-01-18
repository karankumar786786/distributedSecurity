package one.org.security.api.dto.response;

import java.util.Map;

import jakarta.validation.constraints.NotBlank;

public record CheckUserExistResponseDTO(
        @NotBlank
        boolean exist,
        Map<String, Boolean> data,
        String token
) {}

