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
        AuthorizationEntity entity = toEntity(authorization);
        redisService.saveAuthorizationEntity(entity);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        redisService.removeAuthorization(authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        AuthorizationEntity entity = redisService.findAuthorizationEntityById(id);
        return entity != null ? toObject(entity) : null;
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        AuthorizationEntity entity = redisService.findAuthorizationEntityByToken(token, tokenType);
        return entity != null ? toObject(entity) : null;
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
        RegisteredClient registeredClient = registeredClientRepository.findById(entity.getRegisteredClientId());
        if (registeredClient == null) {
            throw new RuntimeException("Registered client not found: " + entity.getRegisteredClientId());
        }

        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(entity.getId())
                .principalName(entity.getPrincipalName())
                .authorizationGrantType(new AuthorizationGrantType(entity.getAuthorizationGrantType()))
                .authorizedScopes(entity.getAuthorizedScopes())
                .attributes(attrs -> attrs.putAll(entity.getAttributes()));

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
            builder.token(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, t.getTokenValue(), t.getIssuedAt(),
                    t.getExpiresAt(), entity.getAuthorizedScopes()), meta -> meta.putAll(t.getMetadata()));
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
    }
}
