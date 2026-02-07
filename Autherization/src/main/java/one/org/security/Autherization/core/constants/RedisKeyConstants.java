package one.org.security.Autherization.core.constants;

public class RedisKeyConstants {
    public static final String AUTH_ID_PREFIX = "auth:id:";
    public static final String AUTH_CODE_PREFIX = "auth:code:";
    public static final String AUTH_REFRESH_TOKEN_PREFIX = "auth:refresh_token:";
    public static final String AUTH_ACCESS_TOKEN_PREFIX = "auth:access_token:";
    public static final String AUTH_STATE_PREFIX = "auth:state:";
    public static final String CLIENT_PREFIX = "client:";
    public static final String RATE_LIMIT_PREFIX = "ratelimit:";

    private RedisKeyConstants() {
        // Prevent instantiation
    }
}
