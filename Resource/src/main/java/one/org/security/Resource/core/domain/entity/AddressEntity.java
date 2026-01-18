package one.org.security.Resource.core.domain.entity;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AddressEntity {
    private int pincode;
    private String country;
    private String state;
    private String dist;
    private String landmark;
    private String buildingOrFlatName;

}
