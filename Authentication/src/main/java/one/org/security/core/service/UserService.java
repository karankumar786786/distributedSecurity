package one.org.security.core.service;

import org.springframework.data.mongodb.core.query.Query;

import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.stereotype.Service;

import one.org.security.api.Errors.CustomExceptions.ResourceNotFoundException;
import one.org.security.core.domain.entity.User;
import one.org.security.infrastructure.persistence.UserRepository;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private MongoTemplate mongoTemplate;

    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }

    public User getUserByCredentialId(com.yubico.webauthn.data.ByteArray credentialId) {
        return userRepository.findByFidoCredentialCredentialId(credentialId).orElse(null);
    }

    public User saveUser(User user) {
        if (user == null) {
            throw new IllegalArgumentException("cannot save null user");
        }
        return userRepository.save(user);
    }

    public User incrementCompletedOperations(ObjectId userId) {
        Query query = new Query(Criteria.where("_id").is(userId));
        Update update = new Update().inc("numberOfInitaiatedOperations", 1);
        // Find and Modify returns the OLD object by default, so we return the updated
        // one
        return mongoTemplate.findAndModify(query, update,
                org.springframework.data.mongodb.core.FindAndModifyOptions.options().returnNew(true), User.class);
    }

    public void resetCompletedOperations(ObjectId userId) {
        Query query = new Query(Criteria.where("_id").is(userId));
        Update update = new Update().set("numberOfInitaiatedOperations", 0).set("lockingTime", null);
        mongoTemplate.updateFirst(query, update, User.class);
    }

    public User getUserById(ObjectId id) {
        if (id == null) {
            throw new IllegalArgumentException("cannot get null id");
        }
        return userRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("user id not found" + id));
    }

    public void updateBackupEmail(ObjectId userId, String newBackupEmail) {
        Query q = new Query(Criteria.where("_id").is(userId));
        Update u = new Update()
                .set("backupEmail", newBackupEmail)
                .set("backupEmailVerified", false);

        var result = mongoTemplate.updateFirst(q, u, User.class);
        if (result.getMatchedCount() == 0)
            throw new RuntimeException("User not found");
    }

    public void updatePhoneNumber(ObjectId userId, String newPhoneNumber) {
        Query q = new Query(Criteria.where("_id").is(userId));
        Update u = new Update()
                .set("phoneNumber", newPhoneNumber)
                .set("phoneNumberVerified", false);

        var result = mongoTemplate.updateFirst(q, u, User.class);
        if (result.getMatchedCount() == 0)
            throw new RuntimeException("User not found");
    }

    public void updatePassword(ObjectId userId, String hashedPassword) {

        Query q = new Query(Criteria.where("_id").is(userId));
        Update u = new Update().set("password", hashedPassword);

        var result = mongoTemplate.updateFirst(q, u, User.class);
        if (result.getMatchedCount() == 0)
            throw new RuntimeException("User not found");
    }

    public void markBackupEmailVerified(ObjectId userId) {
        Query q = new Query(Criteria.where("_id").is(userId));
        Update u = new Update().set("backupEmailVerified", true);

        var result = mongoTemplate.updateFirst(q, u, User.class);
        if (result.getMatchedCount() == 0)
            throw new RuntimeException("User not found");
    }

    public void markPhoneNumberVerified(ObjectId userId) {
        Query q = new Query(Criteria.where("_id").is(userId));
        Update u = new Update().set("phoneNumberVerified", true);

        var result = mongoTemplate.updateFirst(q, u, User.class);
        if (result.getMatchedCount() == 0)
            throw new RuntimeException("User not found");
    }

}
