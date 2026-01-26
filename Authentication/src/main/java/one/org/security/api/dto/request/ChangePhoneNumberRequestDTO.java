package one.org.security.api.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record ChangePhoneNumberRequestDTO(
                @NotBlank(message = "Phone number cannot be blank") @Pattern(regexp = "^\\+?[0-9]{10,15}$", message = "Invalid phone number format") String phoneNumber) {
}
