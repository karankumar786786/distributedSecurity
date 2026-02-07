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

import lombok.extern.slf4j.Slf4j;
import one.org.security.Autherization.core.domain.entity.AuthorizationEntity;
import one.org.security.Autherization.core.domain.entity.AuthorizationEntity.TokenEntity;
import one.org.security.Autherization.core.service.cache.RedisService;

@Slf4j
@Service
public class CustomAuthcodeService implements OAuth2AuthorizationService {

    @Autowired
    private RedisService redisService;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Override
    public void save(OAuth2Authorization authorization) {
        log.debug("save called for ID: {}", authorization.getId());
        AuthorizationEntity entity = toEntity(authorization);
        log.debug("Saving entity with code: {}",
                (entity.getAuthorizationCode() != null ? entity.getAuthorizationCode().getTokenValue() : "NULL"));
        redisService.saveAuthorizationEntity(entity);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        log.debug("CustomAuthcodeService.remove called for id: {}", authorization.getId());
        redisService.removeAuthorization(authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        log.debug("CustomAuthcodeService.findById called for id: {}", id);
        AuthorizationEntity entity = redisService.findAuthorizationEntityById(id);
        if (entity == null) {
            log.debug("CustomAuthcodeService.findById: Entity not found for id: {}", id);
            return null;
        }
        log.debug("CustomAuthcodeService.findById: Found entity, converting to domain object.");
        return toObject(entity);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        log.debug("CustomAuthcodeService.findByToken called. Token: {}, Type: {}", token,
                (tokenType != null ? tokenType.getValue() : "null"));
        AuthorizationEntity entity = redisService.findAuthorizationEntityByToken(token, tokenType);
        if (entity == null) {
            log.debug("CustomAuthcodeService.findByToken: Entity not found.");
            return null;
        }
        log.debug("CustomAuthcodeService.findByToken: Found entity, converting to domain object {}", entity.getId());
        return toObject(entity);
    }

    private AuthorizationEntity toEntity(OAuth2Authorization authorization) {
        log.debug("toEntity called for ID: {}", authorization.getId());

        java.util.Map<String, Object> attributes = new java.util.HashMap<>(authorization.getAttributes());

        String codeChallenge = null;
        String codeChallengeMethod = null;
        String codeVerifier = null;
        String nonce = null;
        org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest req = null;

        Object authRequest = authorization
                .getAttribute("org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest");
        if (authRequest instanceof org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest) {
            req = (org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest) authRequest;

            codeChallenge = (String) req.getAdditionalParameters().get("code_challenge");
            if (codeChallenge == null)
                codeChallenge = (String) req.getAttribute("code_challenge");

            codeChallengeMethod = (String) req.getAdditionalParameters().get("code_challenge_method");
            if (codeChallengeMethod == null)
                codeChallengeMethod = (String) req.getAttribute("code_challenge_method");

            codeVerifier = (String) req.getAdditionalParameters().get("code_verifier");
            if (codeVerifier == null)
                codeVerifier = (String) req.getAttribute("code_verifier");

            nonce = (String) req.getAdditionalParameters().get("nonce");
            if (nonce == null)
                nonce = (String) req.getAttribute("nonce");

            if (codeChallenge != null) {
                attributes.put("code_challenge", codeChallenge);
                log.debug("toEntity: Promoted code_challenge: {}", codeChallenge);
            }
            if (codeChallengeMethod != null) {
                attributes.put("code_challenge_method", codeChallengeMethod);
                log.debug("toEntity: Promoted code_challenge_method: {}", codeChallengeMethod);
            }
            if (nonce != null) {
                attributes.put("nonce", nonce);
                log.debug("toEntity: Promoted nonce: {}", nonce);
            }

            log.debug("toEntity: Exhaustive AuthRequest Log:");
            log.debug("  Attributes keys: {}", req.getAttributes().keySet());
            req.getAttributes().forEach((k, v) -> log.debug("    Attr: {} = {}", k, v));
            log.debug("  Params keys: {}", req.getAdditionalParameters().keySet());
            req.getAdditionalParameters().forEach((k, v) -> log.debug("    Param: {} = {}", k, v));
            log.debug("  Redirect URI: {}", req.getRedirectUri());
        } else {
            log.warn("toEntity: OAuth2AuthorizationRequest MISSING or wrong type!");
        }

        AuthorizationEntity.AuthorizationEntityBuilder builder = AuthorizationEntity.builder()
                .id(authorization.getId())
                .registeredClientId(authorization.getRegisteredClientId())
                .principalName(authorization.getPrincipalName())
                .authorizationGrantType(authorization.getAuthorizationGrantType().getValue())
                .authorizedScopes(authorization.getAuthorizedScopes())
                .attributes(attributes)
                .state(authorization.getAttribute(OAuth2ParameterNames.STATE))
                .clientState(req != null ? req.getState() : null)
                .codeChallenge(codeChallenge)
                .codeChallengeMethod(codeChallengeMethod)
                .codeVerifier(codeVerifier)
                .nonce(nonce);

        log.debug("toEntity: Tracking State: {}", builder.build().getState());
        log.debug("toEntity: Client State: {}", builder.build().getClientState());

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
        log.debug("toObject called for ID: {}", entity.getId());
        try {
            RegisteredClient registeredClient = registeredClientRepository.findById(entity.getRegisteredClientId());
            if (registeredClient == null) {
                log.error("RegisteredClient NOT FOUND for ID: {}", entity.getRegisteredClientId());
                log.warn("Registered client not found for ID: {}. Treating authorization as invalid.",
                        entity.getRegisteredClientId());
                return null;
            }
            log.debug("Found RegisteredClient: {}", registeredClient.getClientId());

            OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                    .id(entity.getId())
                    .principalName(entity.getPrincipalName())
                    .authorizationGrantType(new AuthorizationGrantType(entity.getAuthorizationGrantType()))
                    .authorizedScopes(entity.getAuthorizedScopes())
                    .attributes(attrs -> {
                        attrs.putAll(entity.getAttributes());
                        log.debug("toObject: Loaded attributes keys: {}", attrs.keySet());

                        // Force restoration from flat fields for maximum reliability
                        if (entity.getCodeChallenge() != null) {
                            attrs.put("code_challenge", entity.getCodeChallenge());
                            log.debug("toObject: Forcing code_challenge from flat field: {}",
                                    entity.getCodeChallenge());
                        }
                        if (entity.getCodeChallengeMethod() != null) {
                            attrs.put("code_challenge_method", entity.getCodeChallengeMethod());
                            log.debug("toObject: Forcing code_challenge_method from flat field: {}",
                                    entity.getCodeChallengeMethod());
                        }
                        if (entity.getCodeVerifier() != null) {
                            attrs.put("code_verifier", entity.getCodeVerifier());
                            log.debug("toObject: Forcing code_verifier from flat field: {}", entity.getCodeVerifier());
                        }
                        if (entity.getNonce() != null) {
                            attrs.put("nonce", entity.getNonce());
                            log.debug("toObject: Forcing nonce from flat field: {}", entity.getNonce());
                        }

                        if (attrs.containsKey(
                                "org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest")) {
                            Object authReqObj = attrs.get(
                                    "org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest");
                            if (authReqObj instanceof org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest) {
                                org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest req = (org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest) authReqObj;
                                log.debug("toObject: OAuth2AuthorizationRequest params keys: {}",
                                        req.getAdditionalParameters().keySet());
                            }
                        }
                    });

            if (entity.getState() != null) {
                builder.attribute(OAuth2ParameterNames.STATE, entity.getState());
                log.debug("toObject: Tracking State restored: {}", entity.getState());
            }

            if (entity.getClientState() != null) {
                // This is important for the final redirect back to the client
                builder.attribute("client_state", entity.getClientState());
                log.debug("toObject: Client State available: {}", entity.getClientState());
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
            log.warn("CustomAuthcodeService.toObject failed: {}", e.getMessage());
            // Return null to indicate the authorization cannot be reconstructed
            // The flow will restart or fail gracefully
            return null;
        }
    }
}
