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
        log.debug("DebugFilter (Pre-AuthCheck) - URI: {}", request.getRequestURI());
        log.debug("Query: {}", request.getQueryString());
        request.getParameterMap()
                .forEach((k, v) -> log.debug("Param {}: {}", k, String.join(",", v)));
        if (auth != null) {
            log.debug("DebugFilter - Auth found: {}, Auth={}, Authorities={}", auth.getName(), auth.isAuthenticated(),
                    auth.getAuthorities());
        } else {
            log.debug("DebugFilter - No Authentication in Context!");
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            log.debug("DebugFilter (Post-Chain) - URI: {}", request.getRequestURI());
            log.debug("Response Status: {}", response.getStatus());
            String location = response.getHeader("Location");
            if (location != null) {
                log.debug("Response Location: {}", location);
            }
        }
    }
}
