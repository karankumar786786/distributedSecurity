package one.org.security.api.Errors.CustomExceptions;

public class UserAlreadyExistException extends RuntimeException {
    public UserAlreadyExistException(String message){
        super(message);
    }
}
