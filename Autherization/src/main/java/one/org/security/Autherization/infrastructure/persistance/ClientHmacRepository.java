package one.org.security.Autherization.infrastructure.persistance;

import org.bson.types.ObjectId;
import org.springframework.data.mongodb.repository.MongoRepository;
import one.org.security.Autherization.core.domain.entity.ClientHmacEntity;

public interface ClientHmacRepository extends MongoRepository<ClientHmacEntity, ObjectId> {

}
