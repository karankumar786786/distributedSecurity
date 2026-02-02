package one.org.security.client.infrastructure.security;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.util.Map;

import com.nimbusds.oauth2.sdk.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

/**
 * Stateless in-memory OAuth2 authorization request repository.
 * Uses short-lived in-memory cache instead of cookies.
 * No cookies are used.
 */
@Component
public class HttpCookieOAuth2AuthorizationRequestRepository
        implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private static final long CACHE_EXPIRATION_MS = 180_000; // 3 minutes

    private void logToFile(String message) {
        try (FileWriter fw = new FileWriter("/Users/rahulgupta/Desktop/distributedSecurity/AuthDebug.txt", true);
                PrintWriter pw = new PrintWriter(fw)) {
            pw.println(LocalDateTime.now() + " - [CLIENT] " + message);
        } catch (Exception e) {
        }
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        logToFile("LOADING AUTHORIZATION REQUEST for URI: " + requestUri);

        // The state parameter is the key to look up the authorization request
        String stateParam = request.getParameter("state");
        if (stateParam == null) {
            logToFile("  No state parameter found for " + requestUri);
            return null;
        }

        OAuth2AuthorizationRequest authRequest = AuthRequestCache.get(stateParam);
        if (authRequest != null) {
            logToFile("  Loaded from cache - State: " + authRequest.getState());
        } else {
            logToFile("  No authorization request found in cache for state: " + stateParam);
        }
        return authRequest;
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request,
            HttpServletResponse response) {
        logToFile("SAVING AUTHORIZATION REQUEST (Stateless - no cookies)");

        if (authorizationRequest == null) {
            logToFile("  Request is null - nothing to save");
            return;
        }

        logToFile("  Client ID: " + authorizationRequest.getClientId());
        logToFile("  State: " + authorizationRequest.getState());
        logToFile("  Challenge: " + authorizationRequest.getAttribute("code_challenge"));

        // Store in in-memory cache with state as key
        AuthRequestCache.put(authorizationRequest.getState(), authorizationRequest);
        logToFile("  Saved to in-memory cache with state key");
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request,
            HttpServletResponse response) {
        logToFile("REMOVING AUTHORIZATION REQUEST");

        String stateParam = request.getParameter("state");
        if (stateParam == null) {
            logToFile("  No state parameter found");
            return null;
        }

        OAuth2AuthorizationRequest authRequest = AuthRequestCache.remove(stateParam);
        if (authRequest != null) {
            logToFile("  Removed from cache - State: " + authRequest.getState());
        } else {
            logToFile("  No request found in cache for state: " + stateParam);
        }
        return authRequest;
    }

    /**
     * Simple in-memory cache for authorization requests.
     * Entries expire after 3 minutes.
     * Thread-safe using ConcurrentHashMap.
     */
    private static class AuthRequestCache {
        private static final Map<String, CacheEntry> cache = new java.util.concurrent.ConcurrentHashMap<>();
        private static final long EXPIRATION_MS = 180_000; // 3 minutes

        static void put(String key, OAuth2AuthorizationRequest value) {
            cleanup();
            cache.put(key, new CacheEntry(value, System.currentTimeMillis() + EXPIRATION_MS));
        }

        static OAuth2AuthorizationRequest get(String key) {
            cleanup();
            CacheEntry entry = cache.get(key);
            if (entry == null || entry.isExpired()) {
                return null;
            }
            return entry.value;
        }

        static OAuth2AuthorizationRequest remove(String key) {
            CacheEntry entry = cache.remove(key);
            if (entry == null || entry.isExpired()) {
                return null;
            }
            return entry.value;
        }

        static void cleanup() {
            cache.entrySet().removeIf(e -> e.getValue().isExpired());
        }

        private static class CacheEntry {
            final OAuth2AuthorizationRequest value;
            final long expiresAt;

            CacheEntry(OAuth2AuthorizationRequest value, long expiresAt) {
                this.value = value;
                this.expiresAt = expiresAt;
            }

            boolean isExpired() {
                return System.currentTimeMillis() > expiresAt;
            }
        }
    }
}
