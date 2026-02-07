package one.org.security.Autherization.infrastructure.security.converter;

import jakarta.servlet.http.HttpServletRequest;
import one.org.security.Autherization.core.domain.entity.UserMockEntity;
import one.org.security.common.Jwt.JwtDTO;
import one.org.security.common.Jwt.JwtService;
import org.bson.types.ObjectId;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;

import lombok.extern.slf4j.Slf4j;

/**
 * JWT-only authentication converter for OAuth2 authorization code requests.
 * Reads JWT from Authorization header - no cookies.
 */
@Slf4j
public class SessionAwareAuthorizationCodeRequestAuthenticationConverter implements AuthenticationConverter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final OAuth2AuthorizationCodeRequestAuthenticationConverter delegate = new OAuth2AuthorizationCodeRequestAuthenticationConverter();

    private final JwtService jwtService;

    public SessionAwareAuthorizationCodeRequestAuthenticationConverter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        // First, try to restore authentication from JWT token
        restoreAuthenticationFromJwt(request);

        // Then delegate to the default converter
        return delegate.convert(request);
    }

    private void restoreAuthenticationFromJwt(HttpServletRequest request) {
        // If already authenticated, skip
        Authentication existing = SecurityContextHolder.getContext().getAuthentication();
        if (existing != null && existing.isAuthenticated()
                && !(existing instanceof org.springframework.security.authentication.AnonymousAuthenticationToken)) {
            return;
        }

        String authHeader = request.getHeader(AUTHORIZATION_HEADER);
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            log.debug("SessionAwareConverter - No JWT token in Authorization header");
            return;
        }

        String token = authHeader.substring(BEARER_PREFIX.length());

        // Get device bind from request attribute (set by ProcessDeviceFilter)
        String rawDeviceBind = (String) request.getAttribute("RAW-DEVICE-BIND");
        if (rawDeviceBind == null) {
            rawDeviceBind = request.getHeader("User-Agent");
        }

        JwtDTO jwtDTO;
        if (rawDeviceBind != null) {
            jwtDTO = jwtService.validateTokenWithDevice(token, rawDeviceBind);
        } else {
            jwtDTO = jwtService.validateToken(token);
        }

        if (jwtDTO == null) {
            log.debug("SessionAwareConverter - JWT validation failed");
            return;
        }

        UserMockEntity user = UserMockEntity.builder()
                .id(new ObjectId(jwtDTO.userId()))
                .username(jwtDTO.username())
                .build();

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                user, null, user.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);
        log.debug("SessionAwareConverter - JWT authentication restored for user: {}", jwtDTO.username());
    }
}
