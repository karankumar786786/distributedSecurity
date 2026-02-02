package one.org.security.common.Jwt;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import one.org.security.common.Hmac.HmacDTO;
import one.org.security.common.Hmac.HmacService;

/**
 * Service for JWT token generation and validation.
 * Uses HMAC-SHA256 for signing, consistent with existing HMAC key
 * infrastructure.
 * Includes device binding for additional security.
 */
@Service
@Slf4j
public class JwtService {

    private static final String CLAIM_USERNAME = "username";
    private static final String CLAIM_DEVICE_HASH = "deviceHash";
    private static final String CLAIM_DEVICE_KEY_ID = "deviceKeyId";

    private final SecretKey signingKey;
    private final long expirationMs;
    private final String issuer;
    private final HmacService hmacService;

    public JwtService(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration-ms:86400000}") long expirationMs, // Default 24 hours
            @Value("${jwt.issuer:auth-server}") String issuer,
            HmacService hmacService) {
        // Use at least 256 bits for HS256
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < 32) {
            // Pad the key if too short (not recommended for production)
            byte[] paddedKey = new byte[32];
            System.arraycopy(keyBytes, 0, paddedKey, 0, Math.min(keyBytes.length, 32));
            keyBytes = paddedKey;
            log.warn("JWT secret is less than 256 bits. Consider using a longer secret.");
        }
        this.signingKey = new SecretKeySpec(keyBytes, "HmacSHA256");
        this.expirationMs = expirationMs;
        this.issuer = issuer;
        this.hmacService = hmacService;
    }

    /**
     * Generates a JWT token for the authenticated user with device binding.
     *
     * @param userId        The user's unique identifier
     * @param username      The username
     * @param rawDeviceBind The raw device fingerprint (User-Agent, etc.)
     * @return JwtDTO containing the generated token
     */
    public JwtDTO generateToken(String userId, String username, String rawDeviceBind) {
        // Create device hash using existing HMAC infrastructure
        HmacDTO deviceHmac = hmacService.encode(rawDeviceBind + userId + username);

        Date now = new Date();
        Date expiration = new Date(now.getTime() + expirationMs);

        String token = Jwts.builder()
                .subject(userId)
                .claim(CLAIM_USERNAME, username)
                .claim(CLAIM_DEVICE_HASH, deviceHmac.signature())
                .claim(CLAIM_DEVICE_KEY_ID, deviceHmac.keyId())
                .issuer(issuer)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(signingKey, Jwts.SIG.HS256)
                .compact();

        log.debug("Generated JWT token for user: {}", username);
        return new JwtDTO(token, userId, username, deviceHmac.signature(), deviceHmac.keyId(),
                expiration.getTime() / 1000);
    }

    /**
     * Validates a JWT token and extracts claims.
     *
     * @param token The JWT token to validate
     * @return JwtDTO with extracted claims, or null if invalid
     */
    public JwtDTO validateToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String userId = claims.getSubject();
            String username = claims.get(CLAIM_USERNAME, String.class);
            String deviceHash = claims.get(CLAIM_DEVICE_HASH, String.class);
            String deviceKeyId = claims.get(CLAIM_DEVICE_KEY_ID, String.class);

            log.debug("Validated JWT token for user: {}", username);
            return new JwtDTO(token, userId, username, deviceHash, deviceKeyId,
                    claims.getExpiration().getTime() / 1000);

        } catch (ExpiredJwtException e) {
            log.warn("JWT token expired: {}", e.getMessage());
            return null;
        } catch (JwtException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Validates a JWT token AND verifies device binding.
     * This ensures the token is used from the same device it was issued to.
     *
     * @param token         The JWT token to validate
     * @param rawDeviceBind The current request's device fingerprint
     * @return JwtDTO with extracted claims if valid and device matches, null
     *         otherwise
     */
    public JwtDTO validateTokenWithDevice(String token, String rawDeviceBind) {
        JwtDTO jwtDTO = validateToken(token);
        if (jwtDTO == null) {
            return null;
        }

        // Verify device binding using HMAC
        String rawSessionBind = rawDeviceBind + jwtDTO.userId() + jwtDTO.username();
        boolean deviceValid = hmacService.verify(new HmacDTO(
                null,
                rawSessionBind,
                jwtDTO.deviceKeyId(),
                jwtDTO.deviceHash()));

        if (!deviceValid) {
            log.warn("Device binding verification failed for user: {}", jwtDTO.username());
            return null;
        }

        log.debug("Device binding verified for user: {}", jwtDTO.username());
        return jwtDTO;
    }

    /**
     * Extracts the username from a token without full validation.
     * Useful for logging/debugging purposes.
     *
     * @param token The JWT token
     * @return The username claim, or null if extraction fails
     */
    public String extractUsername(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return claims.get(CLAIM_USERNAME, String.class);
        } catch (JwtException e) {
            return null;
        }
    }

    /**
     * Checks if a token is expired without throwing exceptions.
     *
     * @param token The JWT token
     * @return true if expired or invalid, false if valid
     */
    public boolean isTokenExpired(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return claims.getExpiration().before(new Date());
        } catch (JwtException e) {
            return true;
        }
    }
}
