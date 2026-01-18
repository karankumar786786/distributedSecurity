package one.org.security.Authorization.core.repository;

import java.util.Optional;

import org.bson.types.ObjectId;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import one.org.security.Authorization.core.domain.entity.clientEntity;

@Repository
public interface ClientRepository extends MongoRepository<clientEntity, ObjectId> {
    Optional<clientEntity> findByClientId(String clientId);
}
