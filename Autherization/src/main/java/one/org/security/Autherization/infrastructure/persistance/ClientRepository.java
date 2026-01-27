package one.org.security.Autherization.infrastructure.persistance;

import java.util.Optional;

import org.bson.types.ObjectId;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import one.org.security.Autherization.core.domain.entity.ClientEntity;

@Repository
public interface ClientRepository extends MongoRepository<ClientEntity, ObjectId> {
    Optional<ClientEntity> findByClientId(String clientId);

    java.util.List<ClientEntity> findByUserId(ObjectId userId);

}
