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
public class TokenRequestDTO {
    @NotBlank(message = "grant_type is required")
    @JsonProperty("grant_type")
    private String grantType;

    @NotBlank(message = "code is required")
    @JsonProperty("code")
    private String code;

    @NotBlank(message = "client_id is required")
    @JsonProperty("client_id")
    private String clientId;

    @NotBlank(message = "client_secret is required")
    @JsonProperty("client_secret")
    private String clientSecret;
}
