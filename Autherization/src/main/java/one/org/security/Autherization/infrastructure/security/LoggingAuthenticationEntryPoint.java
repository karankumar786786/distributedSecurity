package one.org.security.Autherization.infrastructure.security;

import java.io.IOException;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class LoggingAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final String loginFormUrl;

    public LoggingAuthenticationEntryPoint(String loginFormUrl) {
        this.loginFormUrl = loginFormUrl;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {
        log.debug("LoggingAuthenticationEntryPoint - Commencing redirect due to exception: {}",
                authException.getMessage());

        String queryString = request.getQueryString();
        String currentUrl = request.getRequestURL().toString() + (queryString == null ? "" : "?" + queryString);

        String redirectUrl = org.springframework.web.util.UriComponentsBuilder.fromHttpUrl(loginFormUrl)
                .queryParam("return_to", currentUrl)
                .build()
                .toUriString();

        response.sendRedirect(redirectUrl);
    }
}
