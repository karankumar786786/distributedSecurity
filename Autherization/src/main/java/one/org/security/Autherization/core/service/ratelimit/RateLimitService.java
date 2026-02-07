package one.org.security.Autherization.core.service.ratelimit;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;
import one.org.security.Autherization.core.constants.RedisKeyConstants;

/**
 * Rate limiting service using Redis.
 * Implements sliding window rate limiting per client/IP.
 */
@Slf4j
@Service
public class RateLimitService {

    private final StringRedisTemplate stringRedisTemplate;

    // Configuration
    private static final int MAX_REQUESTS_PER_MINUTE = 60; // 60 requests per minute per key
    private static final int MAX_TOKEN_REQUESTS_PER_MINUTE = 20; // Stricter for token endpoint
    private static final int MAX_AUTHORIZE_REQUESTS_PER_MINUTE = 30; // For authorization endpoint
    private static final Duration EXPIRATION = Duration.ofMinutes(1);

    public RateLimitService(StringRedisTemplate stringRedisTemplate) {
        this.stringRedisTemplate = stringRedisTemplate;
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
     * Core rate limiting logic using Redis INCR and EXPIRE
     */
    private boolean isAllowed(String key, int maxRequests) {
        String redisKey = RedisKeyConstants.RATE_LIMIT_PREFIX + key;
        try {
            Long count = stringRedisTemplate.opsForValue().increment(redisKey);
            if (count != null && count == 1) {
                stringRedisTemplate.expire(redisKey, EXPIRATION.getSeconds(), TimeUnit.SECONDS);
            }

            if (count != null && count > maxRequests) {
                log.warn("RATE LIMIT: Blocked request for key: {} (count: {}/{})", key, count, maxRequests);
                return false;
            }
            return true;
        } catch (Exception e) {
            log.error("Error in rate limiting: {}", e.getMessage(), e);
            // Fail open if Redis is down? Or safe default?
            // Failsafe: allow request if Redis is down to prevent outage
            return true;
        }
    }

    /**
     * Get current request count for a key (for monitoring)
     */
    public int getCurrentCount(String key) {
        String redisKey = RedisKeyConstants.RATE_LIMIT_PREFIX + key;
        try {
            String value = stringRedisTemplate.opsForValue().get(redisKey);
            return value != null ? Integer.parseInt(value) : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * Get remaining requests for a key
     */
    public int getRemainingRequests(String key, int maxRequests) {
        int current = getCurrentCount(key);
        return Math.max(0, maxRequests - current);
    }
}
