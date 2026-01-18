package one.org.security.api.dto.response;

public record AuthResponseDTO(
    String accessToken,
    String refreshToken
) {
    
}
