package one.org.security.api.Errors.CustomExceptions;

public class InvalidSessionException extends RuntimeException {
    public InvalidSessionException(String message) {
        super(message);
    }
}
//TODO: handle this