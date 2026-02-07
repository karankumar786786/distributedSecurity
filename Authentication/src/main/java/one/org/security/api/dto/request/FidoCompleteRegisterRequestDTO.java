package one.org.security.api.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class FidoCompleteRegisterRequestDTO {
    @NotBlank(message = "FIDO response cannot be blank")
    private String response; // The JSON response from the authenticator
}
