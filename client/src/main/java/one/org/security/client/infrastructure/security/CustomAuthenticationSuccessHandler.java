package one.org.security.client.infrastructure.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Custom success handler for OAuth2 authentication.
 * No cookies are used - stateless operation.
 */
@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationSuccessHandler.class);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        System.out.println("=== AUTHENTICATION SUCCESS ===");
        System.out.println("Request URI: " + request.getRequestURI());
        System.out.println("Authentication type: " + authentication.getClass().getName());

        logger.info("OAuth2 authentication successful");

        if (authentication.getPrincipal() instanceof OAuth2User) {
            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
            System.out.println("=== OAUTH2 USER DETAILS ===");
            System.out.println("Attributes: " + oAuth2User.getAttributes());
            System.out.println("Authorities: " + oAuth2User.getAuthorities());
            logger.info("User authenticated: {}", oAuth2User.getAttributes());

            // Store user information in session
            request.getSession().setAttribute("user", oAuth2User.getAttributes());
            System.out.println("User stored in session");
        } else {
            System.out.println("WARNING: Principal is not OAuth2User: " + authentication.getPrincipal().getClass());
        }

        // No cookies to clean up - stateless authorization request storage

        // Set default target URL
        setDefaultTargetUrl("/");
        setAlwaysUseDefaultTargetUrl(false);

        System.out.println("=== CALLING SUPER.onAuthenticationSuccess ===");
        super.onAuthenticationSuccess(request, response, authentication);
        System.out.println("=== AUTHENTICATION SUCCESS COMPLETE ===");
    }
}
