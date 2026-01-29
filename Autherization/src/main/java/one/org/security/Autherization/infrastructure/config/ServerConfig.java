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
        };
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        com.nimbusds.jose.jwk.RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private static com.nimbusds.jose.jwk.RSAKey generateRsa() {
        java.security.KeyPair keyPair = generateRsaKey();
        java.security.interfaces.RSAPublicKey publicKey = (java.security.interfaces.RSAPublicKey) keyPair.getPublic();
        java.security.interfaces.RSAPrivateKey privateKey = (java.security.interfaces.RSAPrivateKey) keyPair
                .getPrivate();
        return new com.nimbusds.jose.jwk.RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(java.util.UUID.randomUUID().toString())
                .build();
    }

    private static java.security.KeyPair generateRsaKey() {
        java.security.KeyPair keyPair;
        try {
            java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
}