package one.org.security.Authorization.api.dto;

import java.util.List;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientRegistrationRequestDTO {
    @NotBlank(message = "redirectUrl is required")
    private String redirectUrl;

    @NotBlank(message = "clientName is required")
    private String clientName;

    private List<String> scopes;
}
