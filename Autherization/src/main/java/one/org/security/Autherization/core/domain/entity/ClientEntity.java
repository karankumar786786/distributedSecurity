package one.org.security.Autherization.core.domain.entity;


import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Document(collection = "client")
@Data
@Builder
@AllArgsConstructor
public class ClientEntity {
    @Id
    private ObjectId id;
    private ObjectId userId;
    @Indexed(unique = true)
    private String clientId;
    private String clientSecret;
    private String redirectUrl;
    private boolean writeAllowed;
}
