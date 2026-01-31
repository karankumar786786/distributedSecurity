package one.org.security.core.domain.dto;

public record SecurityIntegrityDTO(
    String password,
    String hashedPassword,
    String integrityHmac,
    String integrityHmacKeyId
) {
    
}
