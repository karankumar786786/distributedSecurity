package one.org.security.api.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class FidoInitResponseDTO {
    private String options;
    private String initToken;

    // Constructor for backward compatibility
    public FidoInitResponseDTO(String options) {
        this.options = options;
        this.initToken = null;
    }
}
