package one.org.security.api.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequestDTO(
                @NotBlank(message = "Old password is required") String oldPassword,
                @NotBlank(message = "New password is required") @Size(min = 8, message = "New password must be at least 8 characters") String newPassword) {
}
