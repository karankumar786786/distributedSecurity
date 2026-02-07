package one.org.security.Autherization.api.error.CustomError;

public class AuthorizationNotFoundException extends RuntimeException {
    public AuthorizationNotFoundException(String message) {
        super(message);
    }
}
