package one.org.security.Authorization.api.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientRegistrationResponseDTO {
    private String clientId;
    private String clientSecret;
    private String openIdHmacSecret;
    private List<String> redirectUrls;
    private List<String> scopes;
    private List<String> clientAuthenticationMethods;
}
