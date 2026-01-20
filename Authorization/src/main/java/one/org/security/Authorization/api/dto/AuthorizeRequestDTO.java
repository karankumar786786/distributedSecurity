package one.org.security.Authorization.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizeRequestDTO {
    @NotBlank(message = "client_id is required")
    @JsonProperty("client_id")
    private String clientId;

    @NotBlank(message = "scope is required")
    @JsonProperty("scope")
    private String scope;
}
