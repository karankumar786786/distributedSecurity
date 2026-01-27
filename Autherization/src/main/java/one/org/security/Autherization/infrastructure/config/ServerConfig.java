package one.org.security.Autherization.infrastructure.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import org.springframework.security.core.Authentication;

import one.org.security.Autherization.core.domain.entity.UserMockEntity;
import one.org.security.Autherization.core.service.Encoding.CustomEncodingService;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.math.BigInteger;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class ServerConfig {

    @Value("${oauth2.server.issuer}")
    private String issuer;

    @Bean
    public PasswordEncoder passwordEncoder(CustomEncodingService customEncodingService) {
        return customEncodingService;
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().issuer(issuer).build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Authentication principal = context.getPrincipal();
                // Principal is the UsernamePasswordAuthenticationToken you set in SessionFilter
                if (principal.getPrincipal() instanceof UserMockEntity user) {
                    context.getClaims().claim("uid", user.getId().toString());
                    context.getClaims().claim("sub", user.getUsername());
                }
            }
        };
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(
            KeyProperties keyProperties) {
        List<JWK> keys = new ArrayList<>();

        if (keyProperties.getPrivateKey() != null && keyProperties.getKeyId() != null) {
            keys.add(parseKey(keyProperties.getPrivateKey(), keyProperties.getKeyId()));
        }

        JWKSet jwkSet = new JWKSet(keys);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private RSAKey parseKey(String keyContent, String keyId) {
        try {
            // Remove header and footer and newlines
            String privateKeyPEM = keyContent
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

            // We need the public key too for JWK.
            // Since we only have private key in properties, we can derive public key from
            // it?
            // RSAPrivateKeyCrtSpec has pub exponent?
            // Wait, usually we need both. But RSAPrivateKey (CRT) has modulus and public
            // exponent.

            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privateKey.getModulus(), BigInteger.valueOf(65537)); // 65537
                                                                                                                       // is
                                                                                                                       // standard
                                                                                                                       // public
                                                                                                                       // exponent
            // Better: cast to RSAPrivateCrtKey if possible to get public exponent
            if (privateKey instanceof RSAPrivateCrtKey) {
                RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) privateKey;
                publicKeySpec = new RSAPublicKeySpec(crtKey.getModulus(), crtKey.getPublicExponent());
            }

            RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(keyId)
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse key with ID: " + keyId, e);
        }
    }

}
