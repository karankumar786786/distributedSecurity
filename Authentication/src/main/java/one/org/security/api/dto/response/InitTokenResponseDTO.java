package one.org.security.api.dto.response;

/**
 * Response DTO for login initialization endpoints.
 * Contains a short-lived init token that replaces cookies.
 */
public record InitTokenResponseDTO(
        String initToken,
        String flowType) {
}
