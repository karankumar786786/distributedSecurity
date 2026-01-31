package one.org.security.Autherization.infrastructure.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import one.org.security.Autherization.core.domain.entity.UserMockEntity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration
public class ServerConfig {

    @Value("${oauth2.server.issuer}")
    private String issuer;

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(issuer)
                .jwkSetEndpoint("/oauth2/jwks") // Explicitly set this path
                .build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            try {
                System.out
                        .println("DEBUG: TokenCustomizer called for token type: " + context.getTokenType().getValue());
                if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                    Authentication principal = context.getPrincipal();
                    if (principal == null) {
                        System.out.println("ERROR: TokenCustomizer Principal is NULL!");
                        return;
                    }
                    System.out.println("DEBUG: TokenCustomizer Principal class: " + principal.getClass().getName());

                    Object principalObj = principal.getPrincipal();

                    if (principalObj == null) {
                        System.out.println(
                                "ERROR: TokenCustomizer Principal Object is NULL! Using Principal Name as sub.");
                        context.getClaims().claim("sub", principal.getName());
                    } else if (principalObj instanceof UserMockEntity user) {
                        System.out.println("DEBUG: Principal is UserMockEntity. Username: " + user.getUsername());
                        context.getClaims().claim("sub", user.getUsername());
                    } else if (principalObj instanceof org.springframework.security.core.userdetails.UserDetails userDetails) {
                        System.out.println("DEBUG: Principal is UserDetails. Username: " + userDetails.getUsername());
                        context.getClaims().claim("sub", userDetails.getUsername());
                    } else {
                        System.out.println("DEBUG: Principal is unknown type: " + principalObj.getClass().getName());
                        context.getClaims().claim("sub", principal.getName());
                    }
                }
                System.out
                        .println("DEBUG: Token Customizer finished for principal: " + context.getPrincipal().getName());
            } catch (Exception e) {
                System.out.println("ERROR: TokenCustomizer CRASHED: " + e.getMessage());
                e.printStackTrace();
                throw e;
            }
        };
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(KeyProperties keyProperties) {
        java.util.List<com.nimbusds.jose.jwk.JWK> keys = new java.util.ArrayList<>();

        com.nimbusds.jose.jwk.RSAKey currentKey = parseKey(keyProperties.getCurrent(), "Current");
        if (currentKey != null) {
            keys.add(currentKey);
        }

        com.nimbusds.jose.jwk.RSAKey oldKey = parseKey(keyProperties.getOld(), "Old");
        if (oldKey != null) {
            keys.add(oldKey);
        }

        JWKSet jwkSet = new JWKSet(keys);

        return (jwkSelector, securityContext) -> {
            // Check if the selector is filtering by Algorithm.
            // If it IS filtering by Algorithm (e.g. RS256) AND NOT filtering by Key ID,
            // it means it's trying to find a key for SIGNING.
            // In this case, we must return ONLY the current key to avoid ambiguity.
            if (jwkSelector.getMatcher().getAlgorithms() != null
                    && !jwkSelector.getMatcher().getAlgorithms().isEmpty()
                    && (jwkSelector.getMatcher().getKeyIDs() == null
                            || jwkSelector.getMatcher().getKeyIDs().isEmpty())) {

                if (currentKey != null) {
                    return java.util.Collections.singletonList(currentKey);
                }
            }

            // Otherwise, for JWKS endpoint (where selector matches everything)
            // or specific verification (where Key ID is provided),
            // return all matching keys (which will include both current and old).
            return jwkSelector.select(jwkSet);
        };
    }

    private com.nimbusds.jose.jwk.RSAKey parseKey(KeyProperties.KeyInfo keyInfo, String label) {
        if (keyInfo == null || keyInfo.getPrivateKey() == null) {
            System.out.println("WARNING: No key configuration found for " + label);
            return null;
        }

        try {
            com.nimbusds.jose.jwk.JWK jwk = com.nimbusds.jose.jwk.JWK
                    .parseFromPEMEncodedObjects(keyInfo.getPrivateKey());
            java.util.List<com.nimbusds.jose.jwk.JWK> jwks = java.util.Collections.singletonList(jwk);

            if (!jwks.isEmpty() && jwks.get(0) instanceof com.nimbusds.jose.jwk.RSAKey) {
                com.nimbusds.jose.jwk.RSAKey rsaKey = (com.nimbusds.jose.jwk.RSAKey) jwks.get(0);
                rsaKey = new com.nimbusds.jose.jwk.RSAKey.Builder(rsaKey.toRSAPublicKey())
                        .privateKey(rsaKey.toRSAPrivateKey())
                        .keyID(keyInfo.getKeyId())
                        .build();
                System.out.println("SUCCESS: Loaded " + label + " RSA Key with ID: " + keyInfo.getKeyId());
                return rsaKey;
            } else {
                System.err.println("ERROR: Could not parse RSA Key for " + label);
            }
        } catch (Exception e) {
            System.err.println("ERROR: Failed to parse " + label + " key: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }
}