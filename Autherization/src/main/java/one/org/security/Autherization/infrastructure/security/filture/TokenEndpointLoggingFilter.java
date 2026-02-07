package one.org.security.Autherization.infrastructure.security.filture;

import java.io.IOException;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class TokenEndpointLoggingFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String requestURI = request.getRequestURI();
        String method = request.getMethod();

        log.debug("FILTER: Entering - {} {} (State: {})", method, requestURI, request.getParameter("state"));

        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);

        try {
            filterChain.doFilter(request, responseWrapper);
        } finally {
            int status = responseWrapper.getStatus();
            String location = responseWrapper.getHeader("Location");

            if (status == 302 && location != null) {
                log.debug("FILTER: Redirecting to: {}", location);
            }

            if (requestURI.equals("/oauth2/token")) {
                log.info("=== TOKEN ENDPOINT RESPONSE ===");
                log.info("Status: {}", status);
                log.info("===============================");
            }

            responseWrapper.copyBodyToResponse();
        }
    }
}
