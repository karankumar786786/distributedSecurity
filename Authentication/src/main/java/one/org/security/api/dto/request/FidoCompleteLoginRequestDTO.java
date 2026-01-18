package one.org.security.api.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class FidoCompleteLoginRequestDTO {

    @NotBlank
    private String response;
}
