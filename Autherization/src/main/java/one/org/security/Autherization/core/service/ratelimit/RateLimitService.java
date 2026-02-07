package one.org.security.Autherization.core.service.ratelimit;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

/**
 * Distributed rate limiting service using Redis.
 * Implements fixed window rate limiting per client/IP.
 */
@Service
@Slf4j
public class RateLimitService {

    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    // Configuration
    private static final int MAX_REQUESTS_PER_MINUTE = 60; // 60 requests per minute per key
    private static final int MAX_TOKEN_REQUESTS_PER_MINUTE = 20; // Stricter for token endpoint
    private static final int MAX_AUTHORIZE_REQUESTS_PER_MINUTE = 30; // For authorization endpoint

    public RateLimitService() {
    }

    /**
     * Check if request is allowed for general endpoints
     * 
     * @param key Unique identifier (IP address, client ID, or combination)
     * @return true if allowed, false if rate limited
     */
    public boolean isAllowed(String key) {
        return isAllowed(key, MAX_REQUESTS_PER_MINUTE);
    }

    /**
     * Check if request is allowed for token endpoint (stricter limit)
     * 
     * @param key Unique identifier
     * @return true if allowed, false if rate limited
     */
    public boolean isTokenRequestAllowed(String key) {
        return isAllowed("token:" + key, MAX_TOKEN_REQUESTS_PER_MINUTE);
    }

    /**
     * Check if request is allowed for authorization endpoint
     * 
     * @param key Unique identifier
     * @return true if allowed, false if rate limited
     */
    public boolean isAuthorizeRequestAllowed(String key) {
        return isAllowed("authorize:" + key, MAX_AUTHORIZE_REQUESTS_PER_MINUTE);
    }

    /**
     * Core rate limiting logic using Redis
     */
    private boolean isAllowed(String key, int maxRequests) {
        String redisKey = "ratelimit:" + key;
        ValueOperations<String, String> ops = stringRedisTemplate.opsForValue();

        try {
            Long count = ops.increment(redisKey);

            if (count != null && count == 1) {
                stringRedisTemplate.expire(redisKey, 1, TimeUnit.MINUTES);
            }

            if (count != null && count > maxRequests) {
                log.warn("RATE LIMIT: Blocked request for key: {} (count: {}/{})", key, count, maxRequests);
                return false;
            }

            return true;
        } catch (Exception e) {
            log.error("Rate limit check failed for key: " + key, e);
            // Fail open principle: if Redis is down, allow the request to prevent outage
            return true;
        }
    }

    /**
     * Get current request count for a key (for monitoring)
     */
    public int getCurrentCount(String key) {
        String redisKey = "ratelimit:" + key;
        String val = stringRedisTemplate.opsForValue().get(redisKey);
        return val != null ? Integer.parseInt(val) : 0;
    }

    /**
     * Get remaining requests for a key
     */
    public int getRemainingRequests(String key, int maxRequests) {
        int current = getCurrentCount(key);
        return Math.max(0, maxRequests - current);
    }
}
