package one.org.security.api.dto.response;

public record SecurityIntegrityKeyCreateResponse(
    String keyId,
    String key
) {
    
}
