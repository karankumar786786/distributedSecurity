package one.org.security.api.Errors.CustomExceptions;

public class DeviceFingerPrintError extends RuntimeException {
    public DeviceFingerPrintError(String message) {
        super(message);
    }
}
// TODO: handle this error in global file