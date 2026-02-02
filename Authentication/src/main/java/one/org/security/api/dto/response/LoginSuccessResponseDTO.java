package one.org.security.api.dto.response;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
public class LoginSuccessResponseDTO {
        private String userId;
        private String username;
        private String token; // JWT token for stateless auth
        private String hash; // Legacy - kept for compatibility
        private String hashKeyId; // Legacy - kept for compatibility

        public LoginSuccessResponseDTO(String userId, String username, String token,
                        String hash, String hashKeyId) {
                this.userId = userId;
                this.username = username;
                this.token = token;
                this.hash = hash;
                this.hashKeyId = hashKeyId;
        }

        // Convenience constructor for JWT-only responses
        public LoginSuccessResponseDTO(String userId, String username, String token) {
                this.userId = userId;
                this.username = username;
                this.token = token;
                this.hash = null;
                this.hashKeyId = null;
        }
}
