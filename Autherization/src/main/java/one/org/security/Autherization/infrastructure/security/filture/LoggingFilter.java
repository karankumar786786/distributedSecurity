package one.org.security.Autherization.infrastructure.security.filture;

import java.io.IOException;
import java.util.Enumeration;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class LoggingFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!request.getRequestURI().contains("/oauth2/")) {
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("================= REQUEST START =================");
        log.info("URI: {}", request.getRequestURI());
        log.debug("Method: {}", request.getMethod());
        log.debug("Query: {}", request.getQueryString());

        log.debug("--- Headers ---");
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            log.trace("{}: {}", headerName, request.getHeader(headerName));
        }

        log.debug("--- Parameters ---");
        request.getParameterMap().forEach((k, v) -> {
            log.debug("{}: {}", k, String.join(",", v));
        });
        log.debug("=================================================");

        try {
            filterChain.doFilter(request, response);
        } finally {
            log.debug("================= RESPONSE END =================");
            log.info("Status: {}", response.getStatus());
            log.debug("Location: {}", response.getHeader("Location"));
            log.debug("=================================================");
        }
    }
}
