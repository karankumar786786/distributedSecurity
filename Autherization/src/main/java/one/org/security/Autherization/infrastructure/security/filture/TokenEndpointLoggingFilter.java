package one.org.security.Autherization.infrastructure.security.filture;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.io.IOException;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class TokenEndpointLoggingFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String requestURI = request.getRequestURI();
        String method = request.getMethod();

        logToFileSync(
                "FILTER: Entering - " + method + " " + requestURI + " (State: " + request.getParameter("state") + ")");

        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);

        try {
            filterChain.doFilter(request, responseWrapper);
        } finally {
            int status = responseWrapper.getStatus();
            String location = responseWrapper.getHeader("Location");

            if (status == 302 && location != null) {
                logToFileSync("FILTER: Redirecting to: " + location);
            }

            if (requestURI.equals("/oauth2/token")) {
                logToFileSync("=== TOKEN ENDPOINT RESPONSE ===");
                logToFileSync("Status: " + status);
                logToFileSync("===============================");
            }

            responseWrapper.copyBodyToResponse();
        }
    }

    private void logToFileSync(String message) {
        try (FileWriter fw = new FileWriter("/Users/rahulgupta/Desktop/distributedSecurity/AuthDebug.txt", true);
                PrintWriter pw = new PrintWriter(fw)) {
            pw.println(LocalDateTime.now() + " - " + message);
        } catch (Exception e) {
        }
    }
}
