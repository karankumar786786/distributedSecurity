package one.org.security.api.dto.response;

/**
 * Response DTO for password recovery flow.
 * Contains a short-lived recovery token that replaces FORGET-PASSWORD-SESSION
 * cookie.
 */
public record RecoveryTokenResponseDTO(
        String recoveryToken,
        String method) {
}
