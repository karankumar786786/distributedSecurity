package one.org.security.Autherization.infrastructure.security.filture;

import java.io.IOException;

import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import one.org.security.Autherization.core.domain.entity.UserMockEntity;
import one.org.security.common.Hmac.HmacDTO;
import one.org.security.common.Hmac.HmacService;

public class SessionFilture extends OncePerRequestFilter {

    @Autowired
    private HmacService hmacService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            System.out.println("=================================================");
            System.out.println("=== SESSION FILTER START ===");
            System.out.println("Request URI: " + request.getRequestURI());
            System.out.println("Request Method: " + request.getMethod());
            System.out.println("Query String: " + request.getQueryString());

            String rawDeviceBind = (String) request.getAttribute("RAW-DEVICE-BIND");
            System.out.println("RAW-DEVICE-BIND attribute: " + rawDeviceBind);

            Cookie[] cookies = request.getCookies();
            System.out.println("DEBUG: SessionFilter - Cookies found: " + (cookies != null ? cookies.length : 0));

            if (cookies != null) {
                System.out.println("=== ALL COOKIES ===");
                for (Cookie c : cookies) {
                    System.out.println("Cookie: " + c.getName() + " = "
                            + c.getValue().substring(0, Math.min(50, c.getValue().length())) + "...");
                }
            }

            // Non-blocking checks: if any check fails, proceed without setting
            // authentication
            if (cookies == null) {
                System.out.println("!!! NO COOKIES FOUND - Proceeding anonymous !!!");
                filterChain.doFilter(request, response);
                return;
            }

            String sessionData = null;
            for (Cookie c : cookies) {
                if ("SESSION".equals(c.getName())) {
                    sessionData = c.getValue();
                    System.out.println("=== SESSION COOKIE FOUND ===");
                    System.out.println("SESSION cookie value: " + sessionData);
                    break;
                }
            }

            if (sessionData == null) {
                System.out.println("!!! NO SESSION COOKIE - Proceeding anonymous !!!");
                filterChain.doFilter(request, response);
                return;
            }

            System.out.println("=== PARSING SESSION DATA ===");
            String[] data = sessionData.split("\\|");
            System.out.println("Session data parts: " + data.length);

            if (data.length < 4) {
                System.out.println("!!! INVALID SESSION FORMAT (expected 4 parts, got " + data.length
                        + ") - Proceeding anonymous !!!");
                filterChain.doFilter(request, response);
                return;
            }

            String userId = data[0];
            String username = data[1];
            String hashedSessionBind = data[2];
            String hashedSessionBindKeyId = data[3];

            System.out.println("Parsed Session Data:");
            System.out.println("  userId: " + userId);
            System.out.println("  username: " + username);
            System.out.println("  hashedSessionBind: "
                    + hashedSessionBind.substring(0, Math.min(20, hashedSessionBind.length())) + "...");
            System.out.println("  hashedSessionBindKeyId: " + hashedSessionBindKeyId);

            // If device bind is missing (e.g. from ProcessDeviceFilter check failure or
            // skip), try to get it from User-Agent header directly
            if (rawDeviceBind == null) {
                System.out.println("=== RAW-DEVICE-BIND is null, using User-Agent fallback ===");
                rawDeviceBind = request.getHeader("User-Agent");
                if (rawDeviceBind == null) {
                    System.out.println("!!! NO RAW-DEVICE-BIND AND NO USER-AGENT - Proceeding anonymous !!!");
                    filterChain.doFilter(request, response);
                    return;
                }
                System.out.println("Using User-Agent as device bind: "
                        + rawDeviceBind.substring(0, Math.min(50, rawDeviceBind.length())) + "...");
            }

            System.out.println("=== HMAC VERIFICATION ===");
            String rawSessionBind = rawDeviceBind + userId + username;
            System.out.println("rawSessionBind constructed (first 50 chars): "
                    + rawSessionBind.substring(0, Math.min(50, rawSessionBind.length())) + "...");

            boolean verifyDevice = hmacService
                    .verify(new HmacDTO(null, rawSessionBind, hashedSessionBindKeyId, hashedSessionBind));
            System.out.println("HMAC Verification Result: " + verifyDevice);

            if (!verifyDevice) {
                System.out
                        .println("!!! HMAC VERIFICATION FAILED for user: " + username + " - Proceeding anonymous !!!");
                filterChain.doFilter(request, response);
                return;
            }

            System.out.println("=== CREATING AUTHENTICATION ===");
            UserMockEntity user = UserMockEntity.builder()
                    .id(new ObjectId(userId))
                    .username(username)
                    .build();

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    user, null, user.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authentication);
            System.out.println("✓✓✓ AUTHENTICATION SET SUCCESSFULLY ✓✓✓");
            System.out.println("User: " + username);
            System.out.println("URI: " + request.getRequestURI());
            System.out.println("Authentication.isAuthenticated(): " + authentication.isAuthenticated());
            System.out.println("Authorities: " + user.getAuthorities());

            // Refresh cookie
            ResponseCookie sessionCookie = ResponseCookie.from("SESSION", sessionData).httpOnly(true)
                    .secure(false)
                    .path("/")
                    .sameSite("Lax")
                    .maxAge(60 * 60 * 24) // 1 day
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, sessionCookie.toString());
            System.out.println("Session cookie refreshed");
            System.out.println("=== SESSION FILTER END ===");
            System.out.println("=================================================");

            filterChain.doFilter(request, response);
        } catch (Exception e) {
            System.out.println("!!! EXCEPTION IN SESSION FILTER !!!");
            System.out.println("Exception: " + e.getClass().getName());
            System.out.println("Message: " + e.getMessage());
            e.printStackTrace();
            logger.error("Error in SessionFilter", e);
            // In case of error, proceed to next filter to avoid blocking valid error
            // handling or other flows
            filterChain.doFilter(request, response);
        }
    }

}
