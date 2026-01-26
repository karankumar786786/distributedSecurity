package one.org.security.api.Errors.CustomExceptions;

public class MailNotSentException extends RuntimeException {
    public MailNotSentException(String message){
        super(message);
    }
}
