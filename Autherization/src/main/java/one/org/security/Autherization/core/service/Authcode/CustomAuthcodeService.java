package one.org.security.Autherization.core.service.Authcode;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import one.org.security.Autherization.core.domain.entity.AuthorizationEntity;
import one.org.security.Autherization.core.domain.entity.AuthorizationEntity.TokenEntity;
import one.org.security.Autherization.core.service.cache.RedisService;

@Service
public class CustomAuthcodeService implements OAuth2AuthorizationService {

    @Autowired
    private RedisService redisService;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Override
    public void save(OAuth2Authorization authorization) {
        System.out.println("DEBUG: CustomAuthcodeService.save called for id: " + authorization.getId());
        AuthorizationEntity entity = toEntity(authorization);
        System.out.println("DEBUG: CustomAuthcodeService saving entity: " + entity);
        redisService.saveAuthorizationEntity(entity);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        System.out.println("DEBUG: CustomAuthcodeService.remove called for id: " + authorization.getId());
        redisService.removeAuthorization(authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        System.out.println("DEBUG: CustomAuthcodeService.findById called for id: " + id);
        AuthorizationEntity entity = redisService.findAuthorizationEntityById(id);
        if (entity == null) {
            System.out.println("DEBUG: CustomAuthcodeService.findById: Entity not found for id: " + id);
            return null;
        }
        System.out.println("DEBUG: CustomAuthcodeService.findById: Found entity, converting to domain object.");
        return toObject(entity);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        System.out.println("DEBUG: CustomAuthcodeService.findByToken called. Token: " + token + ", Type: "
                + (tokenType != null ? tokenType.getValue() : "null"));
        AuthorizationEntity entity = redisService.findAuthorizationEntityByToken(token, tokenType);
        if (entity == null) {
            System.out.println("DEBUG: CustomAuthcodeService.findByToken: Entity not found.");
            return null;
        }
        System.out.println("DEBUG: CustomAuthcodeService.findByToken: Found entity, converting to domain object "
                + entity.getId());
        return toObject(entity);
    }

    private AuthorizationEntity toEntity(OAuth2Authorization authorization) {
        AuthorizationEntity.AuthorizationEntityBuilder builder = AuthorizationEntity.builder()
                .id(authorization.getId())
                .registeredClientId(authorization.getRegisteredClientId())
                .principalName(authorization.getPrincipalName())
                .authorizationGrantType(authorization.getAuthorizationGrantType().getValue())
                .authorizedScopes(authorization.getAuthorizedScopes())
                .attributes(authorization.getAttributes())
                .state(authorization.getAttribute(OAuth2ParameterNames.STATE));

        System.out.println(
                "DEBUG: CustomAuthcodeService.toEntity: Attributes keys: " + authorization.getAttributes().keySet());
        Object authRequest = authorization
                .getAttribute("org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest");
        if (authRequest != null) {
            System.out.println("DEBUG: CustomAuthcodeService.toEntity: OAuth2AuthorizationRequest PRESENT. Type: "
                    + authRequest.getClass().getName());
        } else {
            System.out.println("DEBUG: CustomAuthcodeService.toEntity: OAuth2AuthorizationRequest MISSING!");
        }

        OAuth2Authorization.Token<OAuth2AuthorizationCode> code = authorization.getToken(OAuth2AuthorizationCode.class);
        if (code != null) {
            builder.authorizationCode(toTokenEntity(code));
        }

        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getToken(OAuth2AccessToken.class);
        if (accessToken != null) {
            builder.accessToken(toTokenEntity(accessToken));
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getToken(OAuth2RefreshToken.class);
        if (refreshToken != null) {
            builder.refreshToken(toTokenEntity(refreshToken));
        }

        OAuth2Authorization.Token<OidcIdToken> oidcIdToken = authorization.getToken(OidcIdToken.class);
        if (oidcIdToken != null) {
            builder.oidcIdToken(toTokenEntity(oidcIdToken));
        }

        return builder.build();
    }

    private <T extends org.springframework.security.oauth2.core.OAuth2Token> TokenEntity toTokenEntity(
            OAuth2Authorization.Token<T> token) {
        return TokenEntity.builder()
                .tokenValue(token.getToken().getTokenValue())
                .issuedAt(token.getToken().getIssuedAt())
                .expiresAt(token.getToken().getExpiresAt())
                .metadata(token.getMetadata())
                .claims(token.getToken() instanceof OidcIdToken ? ((OidcIdToken) token.getToken()).getClaims() : null)
                .build();
    }

    private OAuth2Authorization toObject(AuthorizationEntity entity) {
        try {
            RegisteredClient registeredClient = registeredClientRepository.findById(entity.getRegisteredClientId());
            if (registeredClient == null) {
                throw new RuntimeException("Registered client not found: " + entity.getRegisteredClientId());
            }

            OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                    .id(entity.getId())
                    .principalName(entity.getPrincipalName())
                    .authorizationGrantType(new AuthorizationGrantType(entity.getAuthorizationGrantType()))
                    .authorizedScopes(entity.getAuthorizedScopes())
                    .attributes(attrs -> {
                        attrs.putAll(entity.getAttributes());
                        System.out
                                .println("DEBUG: CustomAuthcodeService.toObject: Loaded attributes: " + attrs.keySet());
                        if (attrs.containsKey(
                                "org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest")) {
                            System.out.println(
                                    "DEBUG: CustomAuthcodeService.toObject: OAuth2AuthorizationRequest FOUND in attributes.");
                        } else {
                            System.out.println(
                                    "DEBUG: CustomAuthcodeService.toObject: OAuth2AuthorizationRequest NOT FOUND in attributes!");
                        }
                    });

            if (entity.getState() != null) {
                builder.attribute(OAuth2ParameterNames.STATE, entity.getState());
            }

            if (entity.getAuthorizationCode() != null) {
                TokenEntity t = entity.getAuthorizationCode();
                builder.token(new OAuth2AuthorizationCode(t.getTokenValue(), t.getIssuedAt(), t.getExpiresAt()),
                        meta -> meta.putAll(t.getMetadata()));
            }

            if (entity.getAccessToken() != null) {
                TokenEntity t = entity.getAccessToken();
                builder.token(
                        new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, t.getTokenValue(), t.getIssuedAt(),
                                t.getExpiresAt(), entity.getAuthorizedScopes()),
                        meta -> meta.putAll(t.getMetadata()));
            }

            if (entity.getRefreshToken() != null) {
                TokenEntity t = entity.getRefreshToken();
                builder.token(new OAuth2RefreshToken(t.getTokenValue(), t.getIssuedAt(), t.getExpiresAt()),
                        meta -> meta.putAll(t.getMetadata()));
            }

            if (entity.getOidcIdToken() != null) {
                TokenEntity t = entity.getOidcIdToken();
                builder.token(new OidcIdToken(t.getTokenValue(), t.getIssuedAt(), t.getExpiresAt(), t.getClaims()),
                        meta -> meta.putAll(t.getMetadata()));
            }

            return builder.build();
        } catch (Exception e) {
            System.out.println("ERROR: CustomAuthcodeService.toObject failed: " + e.getMessage());
            e.printStackTrace();
            try (java.io.PrintWriter pw = new java.io.PrintWriter(
                    new java.io.FileWriter("/tmp/auth_debug_error.log", true))) {
                pw.println("Timestamp: " + java.time.Instant.now());
                e.printStackTrace(pw);
            } catch (Exception io) {
                // ignore
            }
            throw e; // Re-throw to ensure the flow fails
        }
    }
}
