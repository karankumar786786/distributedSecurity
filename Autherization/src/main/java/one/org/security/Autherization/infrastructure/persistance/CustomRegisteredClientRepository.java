package one.org.security.Autherization.infrastructure.persistance;

import java.time.Duration;

import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import one.org.security.Autherization.core.domain.entity.ClientEntity;
import one.org.security.Autherization.core.service.Client.ClientService;

@Component
public class CustomRegisteredClientRepository implements RegisteredClientRepository {

    @Autowired
    private ClientService clientService;

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
        try {
            System.out.println("DEBUG: Looking up client: " + clientId);
            ClientEntity client = clientService.findByClientId(clientId);
            if (client == null) {
                System.out.println("DEBUG: Client NOT FOUND: " + clientId);
                return null;
            }
            System.out.println("DEBUG: Found client: " + clientId + ", RedirectURL: " + client.getRedirectUrl());
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
        return builder
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(client.isShowConsentForm())
                        .requireProofKey(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                        .accessTokenTimeToLive(Duration.ofMinutes(5))
                        .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                        .build())
                .build();
    }
}
