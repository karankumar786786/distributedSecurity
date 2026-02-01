package one.org.security.Autherization.infrastructure.security.filture;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class OAuth2DebugFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String uri = request.getRequestURI();
        String method = request.getMethod();

        if (uri.contains("/oauth2/")) {
            System.out.println("==============================================");
            System.out.println("DEBUG: OAuth2DebugFilter - " + method + " " + uri);
            System.out.println("DEBUG: Parameters: " + request.getParameterMap().keySet());
            System.out.println("DEBUG: Has user_oauth_approval: " + request.getParameter("user_oauth_approval"));

            // Show scope parameters
            String[] scopes = request.getParameterValues("scope");
            if (scopes != null) {
                System.out.println("DEBUG: Scope count: " + scopes.length);
                for (int i = 0; i < scopes.length; i++) {
                    System.out.println("DEBUG: Scope[" + i + "]: " + scopes[i]);
                }
            }

            // Check authentication
            org.springframework.security.core.Authentication auth = org.springframework.security.core.context.SecurityContextHolder
                    .getContext().getAuthentication();
            System.out.println("DEBUG: Authentication: "
                    + (auth != null ? auth.getName() + " (authenticated=" + auth.isAuthenticated() + ")" : "null"));
            System.out.println("==============================================");
        }

        filterChain.doFilter(request, response);
    }
}
