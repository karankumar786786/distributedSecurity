package one.org.security.api.dto.response;




public record LoginResponseDTO(
    boolean passKeyLoginAvailable,
    boolean passwordLoginAvailable
) {
    
}
