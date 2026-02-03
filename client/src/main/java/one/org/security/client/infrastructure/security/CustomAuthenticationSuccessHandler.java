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
 * Optional custom success handler.
 * Only use if you need to perform actions after successful OAuth2 login.
 */
@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationSuccessHandler.class);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        logger.info("OAuth2 authentication successful");

        if (authentication.getPrincipal() instanceof OAuth2User oAuth2User) {
            // Extract user info
            String email = oAuth2User.getAttribute("email");
            String name = oAuth2User.getAttribute("name");

            logger.info("User authenticated: email={}, name={}", email, name);

            // OPTIONAL: Store user info in your database, create account, etc.
            // Example: userService.createOrUpdateUser(email, name);

            // User info is already available in session via Spring Security
            // No need to manually store in session
        }

        // Redirect to home page
        setDefaultTargetUrl("/");
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
