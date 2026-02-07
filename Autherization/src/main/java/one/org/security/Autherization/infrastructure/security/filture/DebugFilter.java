package one.org.security.Autherization.infrastructure.security.filture;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class DebugFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.debug("DEBUG: DebugFilter (Pre-AuthCheck) - URI: {}", request.getRequestURI());
        log.debug("DEBUG: Query: {}", request.getQueryString());
        request.getParameterMap()
                .forEach((k, v) -> log.debug("DEBUG: Param {}: {}", k, String.join(",", v)));
        if (auth != null) {
            log.debug("DEBUG: DebugFilter - Auth found: {}, Auth={}, Authorities={}", auth.getName(),
                    auth.isAuthenticated(), auth.getAuthorities());
        } else {
            log.debug("DEBUG: DebugFilter - No Authentication in Context!");
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            log.debug("DEBUG: DebugFilter (Post-Chain) - URI: {}", request.getRequestURI());
            log.debug("DEBUG: Response Status: {}", response.getStatus());
            String location = response.getHeader("Location");
            if (location != null) {
                log.debug("DEBUG: Response Location: {}", location);
            }
        }
    }
}
