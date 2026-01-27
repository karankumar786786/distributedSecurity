package one.org.security.Autherization.api.dto.response;

import java.util.List;

public record GetClientListResponseDTO(
    List<String> clientIds
) {
    
}
