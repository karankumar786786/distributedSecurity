package one.org.security.Authorization.core.service;

import java.util.UUID;

import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import one.org.security.Authorization.core.domain.entity.clientEntity;
import one.org.security.Authorization.core.repository.ClientRepository;

@Service
public class ClientService {

    @Autowired
    private ClientRepository clientRepository;

    public one.org.security.Authorization.api.dto.ClientRegistrationResponseDTO registerClient(String userId,
            one.org.security.Authorization.api.dto.ClientRegistrationRequestDTO request) {
        // Simple registration logic for demo
        clientEntity client = clientEntity.builder()
                .userId(new ObjectId(userId))
                .clientId(UUID.randomUUID().toString())
                .clientSecret(UUID.randomUUID().toString())
                .openIdHmacSecret(UUID.randomUUID().toString())
                .clientAuthenticationMethods(java.util.List.of("client_secret_basic"))
                .redirectUrls(java.util.List.of(request.getRedirectUrl()))
                .scopes(request.getScopes() != null ? request.getScopes() : java.util.List.of("read", "write"))
                .build();
        clientEntity savedClient = clientRepository.save(client);

        return one.org.security.Authorization.api.dto.ClientRegistrationResponseDTO.builder()
                .clientId(savedClient.getClientId())
                .clientSecret(savedClient.getClientSecret())
                .openIdHmacSecret(savedClient.getOpenIdHmacSecret())
                .redirectUrls(savedClient.getRedirectUrls())
                .scopes(savedClient.getScopes())
                .clientAuthenticationMethods(savedClient.getClientAuthenticationMethods())
                .build();
    }

    public clientEntity getClient(String clientId) {
        return clientRepository.findByClientId(clientId).orElse(null);
    }
}
