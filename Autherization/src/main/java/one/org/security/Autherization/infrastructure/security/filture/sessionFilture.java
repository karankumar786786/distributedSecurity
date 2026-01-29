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
            String rawDeviceBind = (String) request.getAttribute("RAW-DEVICE-BIND");
            Cookie[] cookies = request.getCookies();
            System.out.println("DEBUG: SessionFilter - Cookies found: " + (cookies != null ? cookies.length : 0));

            // Non-blocking checks: if any check fails, proceed without setting
            // authentication
            if (cookies == null) {
                filterChain.doFilter(request, response);
                return;
            }

            String sessionData = null;
            for (Cookie c : cookies) {
                if ("SESSION".equals(c.getName())) {
                    sessionData = c.getValue();
                }
            }

            if (sessionData == null) {
                filterChain.doFilter(request, response);
                return;
            }

            String[] data = sessionData.split("\\|");
            if (data.length < 4) {
                filterChain.doFilter(request, response);
                return;
            }

            String userId = data[0];
            String username = data[1];
            String hashedSessionBind = data[2];
            String hashedSessionBindKeyId = data[3];

            // If device bind is missing (e.g. from ProcessDeviceFilter check failure or
            // skip), continue anonymous
            if (rawDeviceBind == null) {
                System.out.println("DEBUG: SessionFilter - WAITING for RAW-DEVICE-BIND. Proceeding anonymous.");
                filterChain.doFilter(request, response);
                return;
            }

            String rawSessionBind = rawDeviceBind + userId + username;
            boolean verifyDevice = hmacService
                    .verify(new HmacDTO(null, rawSessionBind, hashedSessionBindKeyId, hashedSessionBind));

            if (!verifyDevice) {
                System.out.println("DEBUG: SessionFilter - HMAC Verification Failed for user: " + username);
                // If verification fails explicitly, we might want to log it and continue
                // anonymous
                // or return 400. For now, continuing anonymous is safer for the auth flow,
                // preventing hard blocks on potential edge cases, but strict security might
                // require 401.
                // Given the issue, let's treat it as invalid session -> anonymous.
                filterChain.doFilter(request, response);
                 return;
            }

            UserMockEntity user = UserMockEntity.builder()
                    .id(new ObjectId(userId))
                    .username(username)
                    .build();

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    user, null, user.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authentication);
            System.out.println("DEBUG: SessionFilter - Authentication set for user: " + username + " on URI: "
                    + request.getRequestURI());
            System.out.println("DEBUG: Authentication.isAuthenticated() = " + authentication.isAuthenticated());

            // Refresh cookie
            ResponseCookie sessionCookie = ResponseCookie.from("SESSION", sessionData).httpOnly(true)
                    .secure(false)
                    .path("/")
                    .sameSite("Lax")
                    .maxAge(60 * 60 * 24) // 1 day
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, sessionCookie.toString());

            filterChain.doFilter(request, response);
        } catch (Exception e) {
            logger.error("Error in SessionFilter", e);
            // In case of error, proceed to next filter to avoid blocking valid error
            // handling or other flows
            filterChain.doFilter(request, response);
        }
    }

}
