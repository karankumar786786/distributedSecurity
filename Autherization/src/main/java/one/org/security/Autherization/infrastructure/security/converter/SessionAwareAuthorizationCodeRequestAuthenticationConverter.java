package one.org.security.Autherization.infrastructure.security.converter;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import one.org.security.Autherization.core.domain.entity.UserMockEntity;
import one.org.security.common.Hmac.HmacDTO;
import one.org.security.common.Hmac.HmacService;
import org.bson.types.ObjectId;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;

public class SessionAwareAuthorizationCodeRequestAuthenticationConverter implements AuthenticationConverter {

    private final OAuth2AuthorizationCodeRequestAuthenticationConverter delegate = new OAuth2AuthorizationCodeRequestAuthenticationConverter();

    private final HmacService hmacService;

    public SessionAwareAuthorizationCodeRequestAuthenticationConverter(HmacService hmacService) {
        this.hmacService = hmacService;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        // First, try to restore authentication from session cookie
        restoreAuthenticationFromSession(request);

        // Then delegate to the default converter
        return delegate.convert(request);
    }

    private void restoreAuthenticationFromSession(HttpServletRequest request) {
        // If already authenticated, skip
        Authentication existing = SecurityContextHolder.getContext().getAuthentication();
        if (existing != null && existing.isAuthenticated()
                && !(existing instanceof org.springframework.security.authentication.AnonymousAuthenticationToken)) {
            return;
        }

        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return;
        }

        String sessionData = null;
        for (Cookie c : cookies) {
            if ("SESSION".equals(c.getName())) {
                sessionData = c.getValue();
                break;
            }
        }

        if (sessionData == null) {
            return;
        }

        String[] data = sessionData.split("\\|");
        if (data.length < 4) {
            return;
        }

        String userId = data[0];
        String username = data[1];
        String hashedSessionBind = data[2];
        String hashedSessionBindKeyId = data[3];

        // Get device bind from request attribute (set by ProcessDeviceFilter)
        String rawDeviceBind = (String) request.getAttribute("RAW-DEVICE-BIND");
        if (rawDeviceBind == null) {
            // Try to extract from User-Agent directly as fallback
            rawDeviceBind = request.getHeader("User-Agent");
            if (rawDeviceBind == null) {
                return;
            }
        }

        String rawSessionBind = rawDeviceBind + userId + username;
        boolean verifyDevice = hmacService.verify(
                new HmacDTO(null, rawSessionBind, hashedSessionBindKeyId, hashedSessionBind));

        if (!verifyDevice) {
            return;
        }

        UserMockEntity user = UserMockEntity.builder()
                .id(new ObjectId(userId))
                .username(username)
                .build();

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                user, null, user.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);
        System.out.println("DEBUG: SessionAwareConverter - Authentication restored for user: " + username);
    }
}
