package one.org.security.common.dto;

import one.org.security.common.enums.OtpSentMethodEnum;

public record OtpVerificationDTO(
        String username,
        String deviceHash,
        Integer otp,
        String to,
        OtpSentMethodEnum method,
        int attempts) {

}
