package one.org.security.infrastructure.security.filter;

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
import one.org.security.HmacDTO;
import one.org.security.HmacService;
import one.org.security.core.domain.entity.User;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This filture verify device and session and provive userId and clientids in a
 * array of string
 */

public class SessionFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(SessionFilter.class);

    @Autowired
    private HmacService hmacService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String rawDeviceBind = (String) request.getAttribute("RAW-DEVICE-BIND");
            Cookie[] cookies = request.getCookies();
            if (cookies == null) {
                response.sendError(400, "invalid device session - no cookies");
                return;
            }
            String sessionData = null;
            for (Cookie c : cookies) {
                if ("SESSION".equals(c.getName())) {
                    sessionData = c.getValue();
                }
            }

            if (sessionData == null) {
                response.sendError(400, "invalid session - no SESSION cookie");
                return;
            }

            String[] data = sessionData.split("\\|");
            if (data.length < 4) {
                response.sendError(400, "invalid session - malformed data");
                return;
            }
            String userId = data[0];
            String username = data[1];
            String hashedSessionBind = data[2];
            String hashedSessionBindKeyId = data[3];
            String rawSessionBind = rawDeviceBind+userId+username;
            boolean verifyDevice = hmacService.verify(new HmacDTO(null, rawSessionBind, hashedSessionBindKeyId, hashedSessionBind));
            if (!verifyDevice) {
                response.sendError(400, "invalid device session - hmac failed");
                return;
            }


            User user = User.builder()
                    .id(new ObjectId(userId))
                    .username(username)
                    .build();

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    user, null, user.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authentication);
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
            response.sendError(500, "Internal Server Error in SessionFilter: " + e.getMessage());
        }
    }

}
