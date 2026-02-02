package one.org.security.Autherization.infrastructure.security.filture;

import java.io.IOException;

import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import one.org.security.Autherization.core.domain.entity.UserMockEntity;
import one.org.security.common.Jwt.JwtDTO;
import one.org.security.common.Jwt.JwtService;

/**
 * JWT-only session filter for complete stateless authentication.
 * All authentication via Authorization: Bearer {token} header.
 * No cookies are used.
 */
@Slf4j
public class SessionFilture extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    @Autowired
    private JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            log.debug("=== SESSION FILTER START === URI: {}", request.getRequestURI());

            String rawDeviceBind = (String) request.getAttribute("RAW-DEVICE-BIND");
            if (rawDeviceBind == null) {
                rawDeviceBind = request.getHeader("User-Agent");
            }

            // JWT authentication only (stateless)
            if (tryJwtAuthentication(request, rawDeviceBind)) {
                log.debug("JWT authentication successful for: {}", request.getRequestURI());
                filterChain.doFilter(request, response);
                return;
            }

            // No authentication - proceed as anonymous (for OAuth2 endpoints that may not
            // require auth)
            log.debug("No JWT token found - proceeding anonymous for: {}", request.getRequestURI());
            filterChain.doFilter(request, response);

        } catch (Exception e) {
            log.error("Exception in SessionFilter", e);
            filterChain.doFilter(request, response);
        }
    }

    /**
     * Attempt JWT authentication from Authorization header.
     * 
     * @return true if authentication was successful
     */
    private boolean tryJwtAuthentication(HttpServletRequest request, String rawDeviceBind) {
        String authHeader = request.getHeader(AUTHORIZATION_HEADER);

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            log.debug("No JWT token found in Authorization header");
            return false;
        }

        String token = authHeader.substring(BEARER_PREFIX.length());

        JwtDTO jwtDTO;
        if (rawDeviceBind != null) {
            // Validate with device binding
            jwtDTO = jwtService.validateTokenWithDevice(token, rawDeviceBind);
        } else {
            // Fallback to validation without device binding
            jwtDTO = jwtService.validateToken(token);
        }

        if (jwtDTO == null) {
            log.debug("JWT token validation failed");
            return false;
        }

        // Create authenticated user
        UserMockEntity user = UserMockEntity.builder()
                .id(new ObjectId(jwtDTO.userId()))
                .username(jwtDTO.username())
                .build();

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                user, null, user.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Store JWT claims as request attributes
        request.setAttribute("JWT_USER_ID", jwtDTO.userId());
        request.setAttribute("JWT_USERNAME", jwtDTO.username());

        log.info("JWT authentication successful for user: {}", jwtDTO.username());
        return true;
    }
}
