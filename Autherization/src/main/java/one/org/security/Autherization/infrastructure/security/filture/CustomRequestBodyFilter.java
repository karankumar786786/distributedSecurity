package one.org.security.Autherization.infrastructure.security.filture;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

@Slf4j
public class CustomRequestBodyFilter extends OncePerRequestFilter {

    private static final Set<String> SENSITIVE_PARAMS = Set.of("password", "client_secret", "refresh_token", "code");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (request.getRequestURI().contains("/oauth2/authorize") && "POST".equalsIgnoreCase(request.getMethod())) {
            log.debug("CustomRequestBodyFilter - Intercepted POST /oauth2/authorize");
            Map<String, String[]> parameterMap = request.getParameterMap();
            parameterMap.forEach((key, value) -> {
                if (SENSITIVE_PARAMS.contains(key.toLowerCase())) {
                    log.debug("Param '{}' = [REDACTED]", key);
                } else {
                    log.debug("Param '{}' = {}", key, String.join(",", value));
                }
            });
            if (parameterMap.isEmpty()) {
                log.debug("CustomRequestBodyFilter - NO PARAMETERS FOUND!");
            }
        }

        filterChain.doFilter(request, response);
    }
}
