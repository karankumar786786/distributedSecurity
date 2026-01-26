package one.org.security.event.consumer.repository;

import org.bson.types.ObjectId;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import one.org.security.event.consumer.entity.SecurityEvent;

@Repository
public interface SecurityEventRepository extends MongoRepository<SecurityEvent, ObjectId> {

}
