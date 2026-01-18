package one.org.security.api.dto.request;

import jakarta.validation.constraints.NotBlank;

public record VerifyOtpRequestDTO(
        @NotBlank(message = "OTP is required") String otp) {
}
