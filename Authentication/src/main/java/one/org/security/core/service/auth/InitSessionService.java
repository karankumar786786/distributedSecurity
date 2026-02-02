package one.org.security.core.service.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Service for generating and validating short-lived init session tokens.
 * These replace the INIT-SESSION and LOGIN-SESSION cookies.
 */
@Service
public class InitSessionService {

    private final SecretKey signingKey;
    private static final long INIT_TOKEN_EXPIRATION_MS = 5 * 60 * 1000; // 5 minutes
    private static final long RECOVERY_TOKEN_EXPIRATION_MS = 15 * 60 * 1000; // 15 minutes

    public InitSessionService(@Value("${jwt.secret}") String jwtSecret) {
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Generate an init session token for login flow.
     * 
     * @param userId   User ID
     * @param username Username
     * @param flowType LOGIN-PASSWORD-SESSION or LOGIN-FIDO-SESSION
     * @param initData HMAC signature data (signature|keyId)
     * @return JWT token string
     */
    public String generateInitToken(String userId, String username, String flowType, String initData) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "init");
        claims.put("userId", userId);
        claims.put("username", username);
        claims.put("flowType", flowType);
        claims.put("initData", initData);

        return Jwts.builder()
                .claims(claims)
                .subject(userId)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + INIT_TOKEN_EXPIRATION_MS))
                .signWith(signingKey)
                .compact();
    }

    /**
     * Generate a recovery token for password reset flow.
     * 
     * @param userId User ID
     * @param method BACKUP_EMAIL or PHONE_NUMBER
     * @return JWT token string
     */
    public String generateRecoveryToken(String userId, String method) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "recovery");
        claims.put("method", method);
        claims.put("userId", userId);

        return Jwts.builder()
                .claims(claims)
                .subject(userId)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + RECOVERY_TOKEN_EXPIRATION_MS))
                .signWith(signingKey)
                .compact();
    }

    /**
     * Validate and parse an init token.
     * 
     * @param token JWT token
     * @return Claims if valid, null if invalid
     */
    public InitTokenData validateInitToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            if (!"init".equals(claims.get("type", String.class))) {
                return null;
            }

            return new InitTokenData(
                    claims.get("userId", String.class),
                    claims.get("username", String.class),
                    claims.get("flowType", String.class),
                    claims.get("initData", String.class));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Validate and parse a recovery token.
     * 
     * @param token JWT token
     * @return RecoveryTokenData if valid, null if invalid
     */
    public RecoveryTokenData validateRecoveryToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            if (!"recovery".equals(claims.get("type", String.class))) {
                return null;
            }

            return new RecoveryTokenData(
                    claims.get("userId", String.class),
                    claims.get("method", String.class));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Data class for init token claims
     */
    public record InitTokenData(String userId, String username, String flowType, String initData) {
    }

    /**
     * Data class for recovery token claims
     */
    public record RecoveryTokenData(String userId, String method) {
    }
}
