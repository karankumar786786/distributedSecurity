package one.org.security.Authorization.core.repository;

import java.util.List;
import java.util.Optional;

import org.bson.types.ObjectId;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import one.org.security.Authorization.core.domain.entity.userGrantEntity;

@Repository
public interface UserGrantRepository extends MongoRepository<userGrantEntity, ObjectId> {
    Optional<userGrantEntity> findByUserIdAndClientId(ObjectId userId, String clientId);

    List<userGrantEntity> findAllByUserId(ObjectId userId);
}
