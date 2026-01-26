package one.org.security.api.dto.response;


import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
public class LoginSuccessResponseDTO {
        private String userId;
        private String hash;
        private String hashKeyId;
        private String username;

        public LoginSuccessResponseDTO(String userId, String username, String hash,
                        String hashKeyId) {
                this.userId = userId;
                this.hash = hash;
                this.hashKeyId = hashKeyId;
                this.username = username;
        }
}
