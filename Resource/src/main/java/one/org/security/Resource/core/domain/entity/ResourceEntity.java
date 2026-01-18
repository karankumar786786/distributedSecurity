package one.org.security.Resource.core.domain.entity;

import java.util.List;

import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Builder;
import lombok.Data;

@Document(collection = "resource")
@Data
@Builder
public class ResourceEntity {
    @Id
    private ObjectId id;
    private String name;
    private String dob;
    private String displayPicture;
    private List<AddressEntity> addresses;
}
