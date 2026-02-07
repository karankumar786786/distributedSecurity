package one.org.security.Autherization.infrastructure.security;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException, ServletException {

        log.warn("Authentication failed: {}", exception.getMessage());

        HttpStatus status = HttpStatus.UNAUTHORIZED;
        Map<String, Object> data = new HashMap<>();

        if (exception instanceof OAuth2AuthenticationException) {
            OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();
            data.put("error", error.getErrorCode());
            data.put("error_description", error.getDescription());
            data.put("error_uri", error.getUri());
            if (error.getErrorCode().equalsIgnoreCase("invalid_client")) {
                status = HttpStatus.UNAUTHORIZED;
            } else {
                status = HttpStatus.BAD_REQUEST;
            }
        } else {
            data.put("error", "invalid_request");
            data.put("error_description", exception.getMessage());
            status = HttpStatus.UNAUTHORIZED;
        }

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        objectMapper.writeValue(response.getOutputStream(), data);
    }
}
