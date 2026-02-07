package one.org.security.Autherization.infrastructure.security.filture;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class OAuth2DebugFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String uri = request.getRequestURI();
        String method = request.getMethod();

        if (uri.contains("/oauth2/")) {
            log.debug("==============================================");
            log.debug("DEBUG: OAuth2DebugFilter - {} {}", method, uri);
            log.debug("DEBUG: Parameters: {}", request.getParameterMap().keySet());
            log.debug("DEBUG: Has user_oauth_approval: {}", request.getParameter("user_oauth_approval"));

            // Show scope parameters
            String[] scopes = request.getParameterValues("scope");
            if (scopes != null) {
                log.debug("DEBUG: Scope count: {}", scopes.length);
                for (int i = 0; i < scopes.length; i++) {
                    log.debug("DEBUG: Scope[{}]: {}", i, scopes[i]);
                }
            }

            // Check authentication
            org.springframework.security.core.Authentication auth = org.springframework.security.core.context.SecurityContextHolder
                    .getContext().getAuthentication();
            log.debug("DEBUG: Authentication: {}",
                    (auth != null ? auth.getName() + " (authenticated=" + auth.isAuthenticated() + ")" : "null"));
            log.debug("==============================================");
        }

        filterChain.doFilter(request, response);
    }
}
