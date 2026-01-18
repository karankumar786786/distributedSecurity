package one.org.security.core.domain.dto;

import one.org.security.core.domain.enums.OtpSentMethodEnum;

public record OtpVerificationDTO(
        String username,
        String deviceHash,
        Integer otp,
        String to,
        OtpSentMethodEnum method,
        int attempts) {

}
