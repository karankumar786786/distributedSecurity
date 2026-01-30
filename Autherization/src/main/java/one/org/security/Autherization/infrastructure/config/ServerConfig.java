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
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Authentication principal = context.getPrincipal();
                Object principalObj = principal.getPrincipal();

                if (principalObj instanceof UserMockEntity user) {
                    context.getClaims().claim("uid", user.getId().toString());
                    context.getClaims().claim("sub", user.getUsername());
                } else if (principalObj instanceof org.springframework.security.core.userdetails.UserDetails userDetails) {
                    context.getClaims().claim("sub", userDetails.getUsername());
                } else {
                    context.getClaims().claim("sub", principal.getName());
                }
            }
            System.out.println("DEBUG: Token Customizer finished for principal: " + context.getPrincipal().getName());
        };

    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(KeyProperties keyProperties) {
        com.nimbusds.jose.jwk.RSAKey rsaKey = null;
        try {
            // Parses both Private and Public keys from the PEM content in application.yaml
            com.nimbusds.jose.jwk.JWK jwk = com.nimbusds.jose.jwk.JWK
                    .parseFromPEMEncodedObjects(keyProperties.getPrivateKey());
            java.util.List<com.nimbusds.jose.jwk.JWK> jwks = java.util.Collections.singletonList(jwk);

            if (!jwks.isEmpty() && jwks.get(0) instanceof com.nimbusds.jose.jwk.RSAKey) {
                rsaKey = (com.nimbusds.jose.jwk.RSAKey) jwks.get(0);
                // Ensure it has a Key ID
                rsaKey = new com.nimbusds.jose.jwk.RSAKey.Builder(rsaKey.toRSAPublicKey())
                        .privateKey(rsaKey.toRSAPrivateKey())
                        .keyID(keyProperties.getKeyId())
                        .build();
            } else {
                throw new IllegalStateException(
                        "Could not parse RSA Key from configuration. Ensure 'oauth2.keys.private-key' contains both valid RSA Private and Public Keys.");
            }
        } catch (Exception e) {
            throw new IllegalStateException("Error parsing RSA key from configuration", e);
        }

        try {
            if (rsaKey != null && rsaKey.toRSAPrivateKey() == null) {
                System.err.println("WARNING: RSA Private Key is null after parsing!");
            } else if (rsaKey != null) {
                System.out.println("SUCCESS: RSA Private Key loaded successfully.");
            }
        } catch (Exception e) {
            System.err.println("ERROR: Failed to check private key: " + e.getMessage());
        }
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }
}