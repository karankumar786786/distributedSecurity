package one.org.security.common.Jwt;

/**
 * DTO for JWT token data transfer.
 * 
 * @param token       The JWT token string
 * @param userId      The user ID from the token
 * @param username    The username from the token
 * @param deviceHash  The device hash for device binding verification
 * @param deviceKeyId The HMAC key ID used for device hash
 * @param expiresAt   Token expiration timestamp (epoch seconds)
 */
public record JwtDTO(
        String token,
        String userId,
        String username,
        String deviceHash,
        String deviceKeyId,
        Long expiresAt) {
    /**
     * Creates a JwtDTO with just the token (for responses)
     */
    public static JwtDTO ofToken(String token) {
        return new JwtDTO(token, null, null, null, null, null);
    }

    /**
     * Creates a JwtDTO with full claims (after parsing)
     */
    public static JwtDTO ofClaims(String userId, String username, String deviceHash, String deviceKeyId) {
        return new JwtDTO(null, userId, username, deviceHash, deviceKeyId, null);
    }
}
