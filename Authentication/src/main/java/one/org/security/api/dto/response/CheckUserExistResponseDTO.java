package one.org.security.api.dto.response;

import java.util.Map;

import jakarta.validation.constraints.NotBlank;
import one.org.security.common.Hmac.HmacDTO;

public record CheckUserExistResponseDTO(
        @NotBlank
        boolean exist,
        Map<String, Boolean> data,
        HmacDTO initSession,
        @NotBlank
        String userId,
        @NotBlank
        String username
) {}

