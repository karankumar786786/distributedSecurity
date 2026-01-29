package one.org.security.Autherization.infrastructure.security.filture;

import java.io.IOException;
import java.util.Enumeration;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class LoggingFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!request.getRequestURI().contains("/oauth2/")) {
            filterChain.doFilter(request, response);
            return;
        }

        System.out.println("================= REQUEST START =================");
        System.out.println("URI: " + request.getRequestURI());
        System.out.println("Method: " + request.getMethod());
        System.out.println("Query: " + request.getQueryString());

        System.out.println("--- Headers ---");
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            System.out.println(headerName + ": " + request.getHeader(headerName));
        }

        System.out.println("--- Parameters ---");
        request.getParameterMap().forEach((k, v) -> {
            System.out.println(k + ": " + String.join(",", v));
        });
        System.out.println("=================================================");

        try {
            filterChain.doFilter(request, response);
        } finally {
            System.out.println("================= RESPONSE END =================");
            System.out.println("Status: " + response.getStatus());
            System.out.println("Location: " + response.getHeader("Location"));
            System.out.println("=================================================");
        }
    }
}
