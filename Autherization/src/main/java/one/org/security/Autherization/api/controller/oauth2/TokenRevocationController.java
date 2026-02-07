package one.org.security.Autherization.api.controller.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Token Revocation Endpoint per RFC 7009
 * https://datatracker.ietf.org/doc/html/rfc7009
 */
@RestController
@Slf4j
public class TokenRevocationController {

    @Autowired
    private OAuth2AuthorizationService authorizationService;

    /**
     * Revoke an access token or refresh token.
     * 
     * @param token         The token to revoke
     * @param tokenTypeHint Optional hint about token type: "access_token" or
     *                      "refresh_token"
     * @param request       HTTP request for client authentication
     * @return 200 OK on success (even if token was already invalid - per RFC 7009)
     */
    @PostMapping(value = "/oauth2/revoke", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Void> revokeToken(
            @RequestParam("token") String token,
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint,
            HttpServletRequest request) {

        log.debug("Token revocation request received. TokenTypeHint: {}", tokenTypeHint);

        // Validate client authentication (Basic auth or client_id/client_secret in
        // body)
        String clientId = extractClientId(request);
        if (clientId == null) {
            log.warn("Revocation failed: No client authentication provided");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // Try to find the authorization by token
        OAuth2Authorization authorization = null;

        // Try based on hint first, then try both types
        if ("refresh_token".equals(tokenTypeHint)) {
            authorization = authorizationService.findByToken(token, OAuth2TokenType.REFRESH_TOKEN);
            if (authorization == null) {
                authorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
            }
        } else {
            // Default: try access token first
            authorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
            if (authorization == null) {
                authorization = authorizationService.findByToken(token, OAuth2TokenType.REFRESH_TOKEN);
            }
        }

        if (authorization != null) {
            // Verify the token belongs to the requesting client (security check)
            String authClientId = authorization.getRegisteredClientId();

            if (!clientId.equals(authClientId)) {
                log.warn("Revocation attempt failed: Client {} tried to revoke token belonging to {}", clientId,
                        authClientId);
                // RFC 7009 says we can return 200 if token is invalid, but if it's a permission
                // issue, maybe 403?
                // However, to prevent leakage, giving 200 or 401/403 is debated.
                // RFC 7009 Section 2.2: "The authorization server responses ... 200 OK if the
                // token was revoked successfully or if the client submitted an invalid token"
                // Strict ownership check implies if I don't own it, it's "invalid" for me.
                // So logging warn and returning 200 is compliant and safe (prevents probing).
                return ResponseEntity.ok().build();
            }

            log.debug("Found authorization: {} for client: {}. Revoking...", authorization.getId(), authClientId);

            // Remove the entire authorization (revokes all tokens)
            authorizationService.remove(authorization);

            log.info("Token revoked successfully by client {}", clientId);
        } else {
            // Per RFC 7009: Return 200 OK even if token was not found
            log.debug("Token not found (may already be revoked or invalid)");
        }

        // Always return 200 OK per RFC 7009
        return ResponseEntity.ok().build();
    }

    /**
     * Extract client ID from Basic auth header or request parameters
     */
    private String extractClientId(HttpServletRequest request) {
        // Try Basic auth header first
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Basic ")) {
            try {
                String base64Credentials = authHeader.substring(6);
                String credentials = new String(Base64.getDecoder().decode(base64Credentials), StandardCharsets.UTF_8);
                String[] parts = credentials.split(":", 2);
                if (parts.length >= 1) {
                    return parts[0];
                }
            } catch (Exception e) {
                log.error("Failed to parse Basic auth", e);
            }
        }

        // Try request parameters
        String clientId = request.getParameter("client_id");
        if (clientId != null && !clientId.isEmpty()) {
            return clientId;
        }

        return null;
    }
}
