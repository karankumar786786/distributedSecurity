package one.org.security.Autherization.infrastructure.security;

import java.io.IOException;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class LoggingAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final AuthenticationEntryPoint delegate;

    public LoggingAuthenticationEntryPoint(String loginFormUrl) {
        this.delegate = new LoginUrlAuthenticationEntryPoint(loginFormUrl);
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {
        System.out.println("DEBUG: LoggingAuthenticationEntryPoint - Commencing redirect due to exception: "
                + authException.getMessage());
        authException.printStackTrace();
        delegate.commence(request, response, authException);
    }
}
