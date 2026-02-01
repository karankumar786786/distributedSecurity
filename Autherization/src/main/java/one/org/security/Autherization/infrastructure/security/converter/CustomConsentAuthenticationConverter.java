package one.org.security.Autherization.infrastructure.security.converter;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

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

        System.out.println("DEBUG: CustomConsentConverter - Attempting conversion for " + request.getRequestURI());

        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        String state = request.getParameter(OAuth2ParameterNames.STATE);

        System.out.println("DEBUG: CustomConsentConverter - client_id: " + clientId + ", state: " + state);

        if (!StringUtils.hasText(clientId) || !StringUtils.hasText(state)) {
            System.out.println("DEBUG: CustomConsentConverter - Missing client_id or state. Returning null.");
            // We should let the delegate fail or handle it, but logging is key here.
        }

        Authentication principal = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("DEBUG: CustomConsentConverter - Principal: " + principal);
        if (principal == null || !principal.isAuthenticated()) {
            System.out.println("DEBUG: CustomConsentConverter - Principal is null or not authenticated!");
        }

        Authentication result = delegate.convert(request);
        if (result == null) {
            System.out.println("DEBUG: CustomConsentConverter - Delegate returned NULL. Conversion failed.");
        } else {
            System.out.println("DEBUG: CustomConsentConverter - Conversion SUCCESS: " + result);
        }
        return result;
    }
}
