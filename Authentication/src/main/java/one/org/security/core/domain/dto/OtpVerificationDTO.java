package one.org.security.core.domain.dto;

import one.org.security.api.dto.enums.OtpSentMethodEnum;

public record OtpVerificationDTO(
        String username,
        Integer otp,
        String to,
        OtpSentMethodEnum method,
        int attempts) {

}
