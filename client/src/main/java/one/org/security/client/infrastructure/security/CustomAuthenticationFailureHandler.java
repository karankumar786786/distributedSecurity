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
import java.io.FileWriter;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.io.StringWriter;

/**
 * Custom failure handler for OAuth2 authentication.
 * No cookies are used - stateless operation.
 */
@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

        private static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationFailureHandler.class);

        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                        AuthenticationException exception) throws IOException, ServletException {

                System.out.println("=== AUTHENTICATION FAILURE ===");
                System.out.println("Request URI: " + request.getRequestURI());
                System.out.println("Exception type: " + exception.getClass().getName());
                System.out.println("!!! CRITICAL FAILURE !!!: " + exception.getMessage());

                logToFile("CLIENT AUTH FAILURE: " + exception.getMessage());
                if (exception.getCause() != null) {
                        logToFile("  Cause: " + exception.getCause().getMessage());
                }

                StringWriter sw = new StringWriter();
                exception.printStackTrace(new PrintWriter(sw));
                logToFile("  Stack Trace: " + sw.toString());

                exception.printStackTrace();
                logger.error("OAuth2 authentication failed: {}", exception.getMessage(), exception);

                // No cookies to clean up - stateless authorization request storage

                // Redirect to login page with error
                setDefaultFailureUrl("/login?error=true");

                System.out.println("=== CALLING SUPER.onAuthenticationFailure ===");
                super.onAuthenticationFailure(request, response, exception);
                System.out.println("=== AUTHENTICATION FAILURE COMPLETE ===");
        }

        private void logToFile(String message) {
                try (FileWriter fw = new FileWriter("/Users/rahulgupta/Desktop/distributedSecurity/AuthDebug.txt",
                                true);
                                PrintWriter pw = new PrintWriter(fw)) {
                        pw.println(LocalDateTime.now() + " - [CLIENT] " + message);
                } catch (Exception e) {
                        // Ignore log errors
                }
        }
}
