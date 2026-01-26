package one.org.security.api.Errors.CustomExceptions;



public class ResourceNotFoundException extends RuntimeException {
    public ResourceNotFoundException(String message){
        super(message);
    }
}
