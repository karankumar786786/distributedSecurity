package one.org.security.api.Errors;

public class CentralErrorMessageResponse {
    public static final String VALIDATION_FAILED = "Validation failed";
    public static final String RESOURCE_NOT_FOUND = "Resource not found";
    public static final String BAD_REQUEST = "Bad request";
    public static final String AUTH_FAILED = "Authentication failed";
    public static final String ACCESS_DENIED = "Access denied";
    public static final String METHOD_NOT_ALLOWED = "HTTP method not allowed";
    public static final String INTERNAL_ERROR = "Internal server error";
    public static final String USER_ALREADY_EXIST_ERROR = "User already exist error";
    public static final String INVALID_JSON_ERROR = "Invalid json error";
    public static final String INTERNAL_ERROR_MESSAGE = "Something went wrong. Please try again later";
    public static final String ACCESSS_DENIED_MESSAGE = "You dont have permission to access the resource";
    public static final String UNAUTHORIZED = "authorization faild";

    public CentralErrorMessageResponse(){}
}
