package one.org.security.Autherization.infrastructure.security.filture;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import one.org.security.Autherization.core.service.ratelimit.RateLimitService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Rate limiting filter for OAuth2 endpoints.
 * Applies different limits based on endpoint type.
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    @Autowired
    private RateLimitService rateLimitService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        String clientKey = extractClientKey(request);

        boolean allowed = true;

        // Apply endpoint-specific rate limits
        if (path.startsWith("/oauth2/token")) {
            allowed = rateLimitService.isTokenRequestAllowed(clientKey);
        } else if (path.startsWith("/oauth2/authorize")) {
            allowed = rateLimitService.isAuthorizeRequestAllowed(clientKey);
        } else if (path.startsWith("/oauth2/")) {
            // Other OAuth2 endpoints (revoke, introspect, etc.)
            allowed = rateLimitService.isAllowed(clientKey);
        }

        if (!allowed) {
            // Return 429 Too Many Requests
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(
                    "{\"error\":\"too_many_requests\",\"error_description\":\"Rate limit exceeded. Please try again later.\"}");
            response.setHeader("Retry-After", "60"); // Suggest retry after 60 seconds
            return;
        }

        // Add rate limit headers for transparency
        response.setHeader("X-RateLimit-Limit", "60");
        response.setHeader("X-RateLimit-Remaining",
                String.valueOf(rateLimitService.getRemainingRequests(clientKey, 60)));

        filterChain.doFilter(request, response);
    }

    /**
     * Extract a unique key for rate limiting.
     * Uses combination of IP address and client_id if available.
     */
    private String extractClientKey(HttpServletRequest request) {
        StringBuilder key = new StringBuilder();

        // Get client IP (consider X-Forwarded-For for proxied requests)
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty()) {
            ip = request.getRemoteAddr();
        } else {
            // Take first IP if multiple
            ip = ip.split(",")[0].trim();
        }
        key.append(ip);

        // Add client_id if present (from query param or form data)
        String clientId = request.getParameter("client_id");
        if (clientId != null && !clientId.isEmpty()) {
            key.append(":").append(clientId);
        }

        return key.toString();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        // Only filter OAuth2 endpoints
        return !path.startsWith("/oauth2/");
    }
}
