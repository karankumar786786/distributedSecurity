package one.org.security.client.infrastructure.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Optional custom failure handler.
 * Provides better logging and user-friendly error messages.
 */
@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

        private static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationFailureHandler.class);

        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                        AuthenticationException exception) throws IOException, ServletException {

                logger.error("OAuth2 authentication failed", exception);

                // Set user-friendly error message
                String errorMessage = "Authentication failed. Please try again.";

                if (exception.getMessage() != null) {
                        if (exception.getMessage().contains("access_denied")) {
                                errorMessage = "You denied access. Please authorize the application to continue.";
                        } else if (exception.getMessage().contains("invalid_grant")) {
                                errorMessage = "Invalid authorization code. Please try logging in again.";
                        }
                }

                // Redirect to login with error parameter
                setDefaultFailureUrl("/login?error=true&message=" +
                                java.net.URLEncoder.encode(errorMessage, "UTF-8"));

                super.onAuthenticationFailure(request, response, exception);
        }
}
