package one.org.security.infrastructure.persistence;

import java.util.Optional;

import org.bson.types.ObjectId;
import org.springframework.data.mongodb.repository.MongoRepository;
// import org.springframework.data.mongodb.repository.Query;
// import org.springframework.data.mongodb.repository.Update;
import org.springframework.stereotype.Repository;

import one.org.security.core.domain.entity.User;

@Repository
public interface UserRepository extends MongoRepository<User, ObjectId> {
    Optional<User> findByUsername(String username);

    Optional<User> findByFidoCredentialCredentialId(com.yubico.webauthn.data.ByteArray credentialId);
    void deleteByUsername(String username);
    // @Query("{ _id: ?0 }")
    // @Update("{ $set: { backupEmail: ?1, backupEmailIsVerified: false } }")
    // long updateBackupEmail(ObjectId id, String backupEmail);
    // @Query("{ _id: ?0 }")
    // @Update("{ $set: { phoneNumber: ?1, phoneNumberVerified: false } }")
    // long updatePhoneNumber(ObjectId id, String phoneNumber);
    // @Query("{ _id: ?0 }")
    // @Update("{ $set: { password: ?1 } }")
    // long updatePassword(ObjectId id, String hashedPassword);
}
