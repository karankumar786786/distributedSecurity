package one.org.security.Autherization.core.domain.entity;

import java.io.Serializable;

import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Document(collection = "client")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ClientEntity implements Serializable {
    private static final long serialVersionUID = 1L;

    @Id
    private ObjectId id;
    private ObjectId userId;
    @Indexed(unique = true)
    private String clientId;
    private String hashedClientSecretHmac;
    private String redirectUrl;
    private boolean writeAllowed;
    private boolean showConsentForm;
    private boolean allowProfile;
    private boolean allowPersonalData;
}
