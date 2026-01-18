package one.org.security.Authorization.core.domain.entity;

import java.time.LocalDateTime;
import java.util.List;

import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import com.mongodb.lang.NonNull;

import lombok.Builder;
import lombok.Data;

@Document(collection = "user_grant")
@Data
@Builder
public class userGrantEntity {
    @Id
    private ObjectId id;
    @NonNull
    private ObjectId userId;
    @NonNull
    private String openIdConnect;
    @NonNull
    private String clientId;
    @NonNull
    private List<String> grantedScope;
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();
}
