package one.org.security.api.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response DTO for authentication token response.
 * Used for both password and FIDO login completion.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenResponseDTO {
    private String token;
    private String userId;
    private String username;
    private Long expiresAt; // Optional: token expiration time (epoch seconds)
}
