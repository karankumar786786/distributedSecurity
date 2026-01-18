package one.org.security.Authorization.core.service;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import lombok.Data;
import one.org.security.Authorization.core.domain.entity.clientEntity;
import one.org.security.Authorization.core.domain.entity.userGrantEntity;
import one.org.security.Authorization.core.repository.UserGrantRepository;
import one.org.security.common.dto.TokenDTO;
import one.org.security.common.enums.TokenPurposeMessageEnum;
import one.org.security.common.service.JwtService;

@Service
public class OAuth2Service {

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    @Autowired
    private UserGrantRepository userGrantRepository;

    @Autowired
    private JwtService jwtService;

    // Temporary storage for auth codes: code -> userId:clientId:scope
    private static final String AUTH_CODE_PREFIX = "auth_code:";

    public String authorize(String clientId, String userId, List<String> requestedScopes) {
        // Ensure grant exists (simplified: auto-grant if not exists for this demo)
        userGrantEntity grant = userGrantRepository.findByUserIdAndClientId(new ObjectId(userId), clientId)
                .orElseGet(() -> {
                    userGrantEntity newGrant = userGrantEntity.builder()
                            .userId(new ObjectId(userId))
                            .clientId(clientId)
                            .grantedScope(requestedScopes)
                            .openIdConnect("true") // default
                            .build();
                    return userGrantRepository.save(newGrant);
                });

        // Generate Auth Code
        String code = UUID.randomUUID().toString();
        String value = userId + ":" + clientId + ":" + String.join(",", grant.getGrantedScope());

        // Store in Redis (TTL 5 mins)
        redisTemplate.opsForValue().set(AUTH_CODE_PREFIX + code, value, 5, TimeUnit.MINUTES);

        return code;
    }

    public TokenDTO exchangeToken(String code, String clientId, String clientSecret, clientEntity registeredClient) {
        // Validate Client Credentials (simplified)
        if (!registeredClient.getClientSecret().equals(clientSecret)) {
            throw new RuntimeException("Invalid client credentials");
        }

        // Validate Code
        String value = redisTemplate.opsForValue().get(AUTH_CODE_PREFIX + code);
        if (value == null) {
            throw new RuntimeException("Invalid or expired authorization code");
        }

        String[] parts = value.split(":");
        String userId = parts[0];
        String codeClientId = parts[1];
        String scopeStr = parts[2];
        List<String> scopes = List.of(scopeStr.split(","));

        if (!clientId.equals(codeClientId)) {
            throw new RuntimeException("Client ID mismatch");
        }

        // Revoke code
        redisTemplate.delete(AUTH_CODE_PREFIX + code);

        // Generate Tokens
        // Note: For OAuth2, we use the userId and clientId information.
        // TokenDTO requires deviceHash and hmacKeyId.
        // In a real scenario, we might chain this from the original Auth session or
        // generate new ones.
        // For now, we use placeholders or derived values.
        String deviceHash = "oauth2-client-" + clientId;
        String hmacKeyId = "oauth2-hmac";

        // We use JwtService from common to generate tokens.
        // TokenPurposeMessageEnum might need values for OAUTH_ACCESS_TOKEN if
        // different,
        // but re-using ACCESS_TOKEN is fine for now provided expectedPurpose matches.

        // However, JwtService uses keys from properties. We must ensure those keys are
        // set for "ACCESS_TOKEN" purpose.

        // NOTE: The implementation plan said "Update encode/decode to assume scope".

        // IMPORTANT: We need a valid TokenPurpose. Using ACCESS_TOKEN.
        // But wait, JwtService requires keys to be loaded. Authorization service needs
        // JwtProperties.
        // The common module moved JwtProperties, but Authorization service needs to
        // configure it.

        return new TokenDTO(userId, userId, deviceHash, 60, hmacKeyId, TokenPurposeMessageEnum.ACCESS_TOKEN, scopes);
    }

    public String generateJwt(TokenDTO tokenDto) {
        return jwtService.encode(tokenDto);
    }
}
