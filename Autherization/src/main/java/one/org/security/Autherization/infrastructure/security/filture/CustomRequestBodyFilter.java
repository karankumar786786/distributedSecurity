package one.org.security.Autherization.infrastructure.security.filture;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

public class CustomRequestBodyFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (request.getRequestURI().contains("/oauth2/authorize") && "POST".equalsIgnoreCase(request.getMethod())) {
            System.out.println("DEBUG: CustomRequestBodyFilter - Intercepted POST /oauth2/authorize");
            Map<String, String[]> parameterMap = request.getParameterMap();
            parameterMap.forEach((key, value) -> {
                System.out.println("DEBUG: Param '" + key + "' = " + String.join(",", value));
            });
            if (parameterMap.isEmpty()) {
                System.out.println("DEBUG: CustomRequestBodyFilter - NO PARAMETERS FOUND!");
            }
        }

        filterChain.doFilter(request, response);
    }
}
