package one.org.security.Autherization.infrastructure.config;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
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

import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

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
                if (principal.getPrincipal() instanceof UserMockEntity user) {
                    context.getClaims().claim("uid", user.getId().toString());
                    context.getClaims().claim("sub", user.getUsername());
                }
            }
        };
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(KeyProperties keyProperties) {
        List<JWK> keys = new ArrayList<>();
        if (keyProperties.getPrivateKey() != null && keyProperties.getKeyId() != null) {
            keys.add(parseECKey(keyProperties.getPrivateKey(), keyProperties.getKeyId()));
        }
        JWKSet jwkSet = new JWKSet(keys);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private ECKey parseECKey(String keyContent, String keyId) {
        try {
            String privateKeyPEM = keyContent
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(keySpec);

            // Derive Public Key from Private Key for the P-256 Curve
            ECPublicKey publicKey = deriveECPublicKey(privateKey);

            return new ECKey.Builder(Curve.P_256, publicKey)
                    .privateKey(privateKey)
                    .keyID(keyId)
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse EC key with ID: " + keyId, e);
        }
    }

    // Logic to derive EC Public Key from Private Key using the Generator Point
    private ECPublicKey deriveECPublicKey(ECPrivateKey privateKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        java.security.spec.ECParameterSpec params = privateKey.getParams();

        // Use the private key scalar 's' to find the public point 'W'
        // W = s * G (where G is the generator point of the curve)
        java.math.BigInteger s = privateKey.getS();
        ECPoint w = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util.convertPoint(
                new org.bouncycastle.math.ec.FixedPointCombMultiplier().multiply(
                        org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util.convertSpec(params).getG(),
                        s));

        return (ECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(w, params));
    }
}