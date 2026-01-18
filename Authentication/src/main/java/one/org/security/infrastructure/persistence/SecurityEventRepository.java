package one.org.security.infrastructure.persistence;

import org.bson.types.ObjectId;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import one.org.security.core.domain.entity.SecurityEvent;




@Repository
public interface SecurityEventRepository extends MongoRepository<SecurityEvent,ObjectId>{
    
}
