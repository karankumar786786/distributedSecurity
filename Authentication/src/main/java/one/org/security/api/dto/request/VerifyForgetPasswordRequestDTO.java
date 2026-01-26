package one.org.security.api.dto.request;

import jakarta.validation.constraints.NotBlank;

public record VerifyForgetPasswordRequestDTO(
                @NotBlank(message = "new password cannot be blank") String password,
                @NotBlank(message = "otp cannot be blank") String otp) {
}
