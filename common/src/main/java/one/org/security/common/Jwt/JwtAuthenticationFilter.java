package one.org.security.common.Jwt;

import java.io.IOException;
import java.util.Collections;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT Authentication Filter that extracts and validates JWT tokens from
 * requests.
 * This filter can be used in any service that needs JWT authentication.
 * 
 * It reads the JWT from the Authorization header (Bearer token format)
 * and sets the SecurityContext if the token is valid.
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final boolean requireDeviceVerification;

    /**
     * Creates a filter that requires device verification.
     */
    public JwtAuthenticationFilter(JwtService jwtService) {
        this(jwtService, true);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String authHeader = request.getHeader(AUTHORIZATION_HEADER);

            if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
                log.debug("No JWT token found in Authorization header");
                filterChain.doFilter(request, response);
                return;
            }

            String token = authHeader.substring(BEARER_PREFIX.length());

            JwtDTO jwtDTO;
            if (requireDeviceVerification) {
                // Get device bind from request attribute (set by ProcessDeviceFilter)
                String rawDeviceBind = (String) request.getAttribute("RAW-DEVICE-BIND");
                if (rawDeviceBind == null) {
                    // Fallback to User-Agent
                    rawDeviceBind = request.getHeader("User-Agent");
                }

                if (rawDeviceBind == null) {
                    log.warn("No device binding information available for JWT verification");
                    filterChain.doFilter(request, response);
                    return;
                }

                jwtDTO = jwtService.validateTokenWithDevice(token, rawDeviceBind);
            } else {
                jwtDTO = jwtService.validateToken(token);
            }

            if (jwtDTO == null) {
                log.debug("JWT token validation failed");
                filterChain.doFilter(request, response);
                return;
            }

            // Create authentication principal
            JwtUserPrincipal principal = new JwtUserPrincipal(
                    jwtDTO.userId(),
                    jwtDTO.username());

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    principal,
                    null,
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.debug("JWT authentication successful for user: {}", jwtDTO.username());

            // Store JWT claims as request attributes for downstream use
            request.setAttribute("JWT_USER_ID", jwtDTO.userId());
            request.setAttribute("JWT_USERNAME", jwtDTO.username());

        } catch (Exception e) {
            log.error("Error processing JWT authentication", e);
        }

        filterChain.doFilter(request, response);
    }
}
