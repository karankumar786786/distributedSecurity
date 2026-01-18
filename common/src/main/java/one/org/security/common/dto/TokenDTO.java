package one.org.security.common.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import one.org.security.common.enums.TokenPurposeMessageEnum;

public record TokenDTO(
        @NotBlank(message = "subject is required (username)") String subject,
        @NotBlank(message = "database uniqueId") String id,
        @NotBlank(message = "user devicehash") String deviceHash,
        @Min(value = 1, message = "expiration time must be at least 1 min") int expirationAfterInMinutes,
        @NotBlank(message = "hmac keyId") String hmacKeyId,
        @NotNull(message = "purpose cannot be blank") TokenPurposeMessageEnum purpose) {
}
