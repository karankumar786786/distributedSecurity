package one.org.security.Autherization.infrastructure.security.converter;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

@Slf4j
public class CustomConsentAuthenticationConverter implements AuthenticationConverter {
    private final AuthenticationConverter delegate;

    public CustomConsentAuthenticationConverter(AuthenticationConverter delegate) {
        this.delegate = delegate;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!"POST".equals(request.getMethod()) || !request.getRequestURI().endsWith("/oauth2/authorize")) {
            return null; // Not our request
        }

        log.debug("DEBUG: CustomConsentConverter - Attempting conversion for {}", request.getRequestURI());

        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        String state = request.getParameter(OAuth2ParameterNames.STATE);

        log.debug("DEBUG: CustomConsentConverter - client_id: {}, state: {}", clientId, state);

        if (!StringUtils.hasText(clientId) || !StringUtils.hasText(state)) {
            log.debug("DEBUG: CustomConsentConverter - Missing client_id or state. Returning null.");
            // We should let the delegate fail or handle it, but logging is key here.
        }

        Authentication principal = SecurityContextHolder.getContext().getAuthentication();
        log.debug("DEBUG: CustomConsentConverter - Principal: {}", principal);
        if (principal == null || !principal.isAuthenticated()) {
            log.debug("DEBUG: CustomConsentConverter - Principal is null or not authenticated!");
        }

        Authentication result = delegate.convert(request);
        if (result == null) {
            log.debug("DEBUG: CustomConsentConverter - Delegate returned NULL. Conversion failed.");
        } else {
            log.debug("DEBUG: CustomConsentConverter - Conversion SUCCESS: {}", result);
        }
        return result;
    }
}
