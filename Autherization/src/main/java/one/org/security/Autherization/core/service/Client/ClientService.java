package one.org.security.Autherization.core.service.Client;

import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import one.org.security.Autherization.api.error.CustomError.ClientNotFoundException;
import one.org.security.Autherization.core.domain.entity.ClientEntity;
import one.org.security.Autherization.core.service.Encoding.CustomEncodingService;
import one.org.security.Autherization.core.service.cache.RedisService;
import one.org.security.Autherization.infrastructure.persistance.ClientRepository;

@Service
public class ClientService {
    @Autowired
    private ClientRepository clientRepository;

    @Autowired
    private RedisService redisService;

    @Autowired
    private CustomEncodingService customEncodingService;

    public ClientEntity findByClientId(String clientId) {
        ClientEntity cachedClient = redisService.getClient(clientId);
        if (cachedClient != null) {
            return cachedClient;
        }
        ClientEntity client = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new ClientNotFoundException("Client not found: " + clientId));
        redisService.saveClient(client);
        return client;
    }

    public void saveClient(ClientEntity client) {
        client.setClientSecret(customEncodingService.encode(client.getClientSecret()));
        clientRepository.save(client);
        redisService.saveClient(client);
    }

    public ClientEntity findById(ObjectId id) {
        return clientRepository.findById(id)
                .orElseThrow(() -> new ClientNotFoundException("Client not found with id: " + id));
    }
}
