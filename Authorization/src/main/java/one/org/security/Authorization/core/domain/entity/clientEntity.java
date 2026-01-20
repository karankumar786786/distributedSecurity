package one.org.security.Authorization.core.domain.entity;

import java.util.List;

import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import com.mongodb.lang.NonNull;

import lombok.Builder;
import lombok.Data;

@Document(collection = "client")
@Data
@Builder
public class clientEntity {
    @Id
    private ObjectId id;
    @NonNull
    private ObjectId userId;
    @NonNull
    private String clientId;
    private String clientSecret;
    private String openIdHmacSecret;
    private List<String> clientAuthenticationMethods;
    private List<String> redirectUrls;
    private List<String> scopes;
}
