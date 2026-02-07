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
@Slf4j
@RestController
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

        log.debug("=== TOKEN REVOCATION REQUEST ===");
        log.debug("Token type hint: {}", tokenTypeHint);

        // Validate client authentication (Basic auth or client_id/client_secret in
        // body)
        String clientId = extractClientId(request);
        if (clientId == null) {
            log.warn("ERROR: No client authentication provided");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        log.debug("Client ID: {}", clientId);

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

            if (!authClientId.equals(clientId)) {
                log.warn("Revocation attempt failed: Client ID mismatch. Requester: {}, Token Owner: {}", clientId,
                        authClientId);
                // Return 200 OK to avoid leaking information about token existence/ownership
                // per RFC 7009?
                // Or 403? RFC 7009 says: "The authorization server ... returns a 200 OK status
                // code if the token was successfully revoked or if the token is invalid."
                // However, if the client is not authorized to revoke the token (ownership
                // mismatch),
                // returning 200 OK without revoking might be misleading, but safer.
                // But returning 403 is more explicit about the permission error.
                // Let's stick to 403 for ownership mismatch to be safe internally.
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }

            log.debug("Found authorization: {} for client: {}", authorization.getId(), authClientId);
            log.debug("Removing authorization...");

            // Remove the entire authorization (revokes all tokens)
            authorizationService.remove(authorization);

            log.info("Token revoked successfully for client: {}", clientId);
        } else {
            // Per RFC 7009: Return 200 OK even if token was not found
            log.debug("Token not found (may already be revoked or invalid)");
        }

        log.debug("=== TOKEN REVOCATION COMPLETE ===");

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
                log.error("Failed to parse Basic auth: {}", e.getMessage());
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
