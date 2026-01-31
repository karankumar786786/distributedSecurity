package one.org.security.core.domain.entity;

import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Document("security_fido_keys")
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class SecurityIntegrityFidoKeyEntity {
    @Id
    private ObjectId id;
    private String key;
}
