package one.org.security.Autherization.infrastructure.security.filture;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class DebugFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("DEBUG: DebugFilter (Pre-AuthCheck) - URI: " + request.getRequestURI());
        System.out.println("DEBUG: Query: " + request.getQueryString());
        request.getParameterMap()
                .forEach((k, v) -> System.out.println("DEBUG: Param " + k + ": " + String.join(",", v)));
        if (auth != null) {
            System.out.println("DEBUG: DebugFilter - Auth found: " + auth.getName() + ", Auth=" + auth.isAuthenticated()
                    + ", Authorities=" + auth.getAuthorities());
        } else {
            System.out.println("DEBUG: DebugFilter - No Authentication in Context!");
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            System.out.println("DEBUG: DebugFilter (Post-Chain) - URI: " + request.getRequestURI());
            System.out.println("DEBUG: Response Status: " + response.getStatus());
            String location = response.getHeader("Location");
            if (location != null) {
                System.out.println("DEBUG: Response Location: " + location);
            }
        }
    }
}
