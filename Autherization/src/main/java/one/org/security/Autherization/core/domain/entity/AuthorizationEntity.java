package one.org.security.Autherization.core.domain.entity;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizationEntity implements java.io.Serializable {
    private static final long serialVersionUID = 1L;

    private String id;
    private String registeredClientId;
    private String principalName;
    private String authorizationGrantType;
    private Set<String> authorizedScopes;
    private Map<String, Object> attributes;
    private String state;
    private String clientState;

    private String codeChallenge;
    private String codeChallengeMethod;
    private String codeVerifier;
    private String nonce;

    private TokenEntity authorizationCode;
    private TokenEntity accessToken;
    private TokenEntity refreshToken;
    private TokenEntity oidcIdToken;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TokenEntity implements java.io.Serializable {
        private static final long serialVersionUID = 1L;

        private String tokenValue;
        private Instant issuedAt;
        private Instant expiresAt;
        private Map<String, Object> metadata;
        private Map<String, Object> claims; // For OidcIdToken
    }
}
