package one.org.security.api.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record ChangeBackupEmailRequestDTO(
                @NotBlank(message = "Backup email cannot be blank") @Email(message = "Invalid email format") String backupEmail) {
}
