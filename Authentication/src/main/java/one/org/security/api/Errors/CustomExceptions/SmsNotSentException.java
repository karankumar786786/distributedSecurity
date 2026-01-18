package one.org.security.api.Errors.CustomExceptions;

public class SmsNotSentException extends RuntimeException {
    public SmsNotSentException(String message) {
        super(message);
    }
}
