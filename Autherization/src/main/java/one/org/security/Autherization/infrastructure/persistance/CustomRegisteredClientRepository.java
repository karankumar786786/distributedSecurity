package one.org.security.Autherization.infrastructure.persistance;

import java.time.Duration;

import org.bson.types.ObjectId;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import one.org.security.Autherization.core.domain.entity.ClientEntity;
import one.org.security.Autherization.core.service.Client.ClientService;

@Slf4j
public class CustomRegisteredClientRepository implements RegisteredClientRepository {

    public CustomRegisteredClientRepository(ClientService clientService) {
        this.clientService = clientService;
        log.debug("DEBUG: CustomRegisteredClientRepository INSTANTIATED (Manual Bean)");
    }

    private final ClientService clientService;

    @Override
    public void save(RegisteredClient registeredClient) {
        throw new UnsupportedOperationException("this method is not supported");
    }

    @Override
    public RegisteredClient findById(String id) {
        ClientEntity client = clientService.findById(new ObjectId(id));
        return toRegisteredClient(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        log.debug("DEBUG: CustomRegisteredClientRepository.findByClientId CALLED for {}", clientId);
        try {
            ClientEntity client = clientService.findByClientId(clientId);
            if (client == null) {
                return null;
            }
            return toRegisteredClient(client);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private RegisteredClient toRegisteredClient(ClientEntity client) {
        RegisteredClient.Builder builder = RegisteredClient.withId(client.getId().toHexString())
                .clientId(client.getClientId())
                .clientSecret(client.getHashedClientSecretHmac())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(client.getRedirectUrl())
                // Add all supported scopes
                .scope("openid")
                .scope("read")
                .scope("username");
        // Conditionally add write scope based on your MongoDB entity
        if (client.isWriteAllowed()) {
            builder.scope("write");
        }
        if (client.isAllowProfile()) {
            builder.scope("profile");
        }
        if (client.isAllowPersonalData()) {
            builder.scope("personal");
        }
        RegisteredClient registeredClient = builder
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(client.isShowConsentForm())
                        .requireProofKey(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofDays(7))
                        .reuseRefreshTokens(false) // Issue new refresh token on each use (more secure)
                        .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                        .build())
                .build();

        return registeredClient;
    }
}
