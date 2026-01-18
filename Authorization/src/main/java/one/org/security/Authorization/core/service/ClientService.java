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

    public clientEntity registerClient(String userId, String redirectUrl) {
        // Simple registration logic for demo
        clientEntity client = clientEntity.builder()
                .userId(new ObjectId(userId))
                .clientId(UUID.randomUUID().toString())
                .clientSecret(UUID.randomUUID().toString())
                .clientAuthenticationMethods(java.util.List.of("client_secret_basic"))
                .redirectUrls(java.util.List.of(redirectUrl))
                .scopes(java.util.List.of("read", "write"))
                .build();
        return clientRepository.save(client);
    }

    public clientEntity getClient(String clientId) {
        return clientRepository.findByClientId(clientId).orElse(null);
    }
}
