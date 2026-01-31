package one.org.security.Autherization.core.domain.entity;

import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.AllArgsConstructor;
import lombok.Data;

@Document(collection = "client_hmac_secret")
@Data
@AllArgsConstructor
public class ClientHmacEntity {
    @Id
    private ObjectId id;
    private String encryptedKey;
}
