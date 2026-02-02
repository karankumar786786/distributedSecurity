package one.org.security.Autherization.core.service.ratelimit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Rate limiting service using Caffeine cache.
 * Implements sliding window rate limiting per client/IP.
 */
@Service
public class RateLimitService {

    // Cache for tracking request counts: key -> AtomicInteger count
    private final Cache<String, AtomicInteger> requestCountCache;

    // Configuration
    private static final int MAX_REQUESTS_PER_MINUTE = 60; // 60 requests per minute per key
    private static final int MAX_TOKEN_REQUESTS_PER_MINUTE = 20; // Stricter for token endpoint
    private static final int MAX_AUTHORIZE_REQUESTS_PER_MINUTE = 30; // For authorization endpoint

    public RateLimitService() {
        this.requestCountCache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(1)) // Reset counters every minute
                .maximumSize(10000) // Max 10k unique keys
                .build();
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
     * Core rate limiting logic
     */
    private boolean isAllowed(String key, int maxRequests) {
        AtomicInteger counter = requestCountCache.get(key, k -> new AtomicInteger(0));
        int currentCount = counter.incrementAndGet();

        if (currentCount > maxRequests) {
            System.out.println("RATE LIMIT: Blocked request for key: " + key +
                    " (count: " + currentCount + "/" + maxRequests + ")");
            return false;
        }

        return true;
    }

    /**
     * Get current request count for a key (for monitoring)
     */
    public int getCurrentCount(String key) {
        AtomicInteger counter = requestCountCache.getIfPresent(key);
        return counter != null ? counter.get() : 0;
    }

    /**
     * Get remaining requests for a key
     */
    public int getRemainingRequests(String key, int maxRequests) {
        int current = getCurrentCount(key);
        return Math.max(0, maxRequests - current);
    }
}
