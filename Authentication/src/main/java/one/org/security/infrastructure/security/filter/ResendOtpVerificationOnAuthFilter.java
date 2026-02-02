package one.org.security.infrastructure.security.filter;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import one.org.security.core.service.auth.InitSessionService;
import one.org.security.core.service.auth.InitSessionService.InitTokenData;
import one.org.security.core.service.auth.InitSessionService.RecoveryTokenData;

/**
 * Filter for OTP resend endpoints.
 * Validates init tokens or recovery tokens from headers (no cookies).
 */
public class ResendOtpVerificationOnAuthFilter extends OncePerRequestFilter {

    @Autowired
    private InitSessionService initSessionService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Try init token first
        String initToken = request.getHeader("X-Init-Token");
        if (initToken != null) {
            InitTokenData tokenData = initSessionService.validateInitToken(initToken);
            if (tokenData != null) {
                request.setAttribute("USERNAME", tokenData.username());
                request.setAttribute("USERID", tokenData.userId());
                request.setAttribute("USER-ID", tokenData.userId());
                request.setAttribute("INIT-SESSION", tokenData.initData());
                request.setAttribute("LOGIN-SESSION", tokenData.flowType());
                filterChain.doFilter(request, response);
                return;
            }
        }

        // Try recovery token
        String recoveryToken = request.getHeader("X-Recovery-Token");
        if (recoveryToken != null) {
            RecoveryTokenData tokenData = initSessionService.validateRecoveryToken(recoveryToken);
            if (tokenData != null) {
                request.setAttribute("USERID", tokenData.userId());
                request.setAttribute("USER-ID", tokenData.userId());
                request.setAttribute("FORGET-PASSWORD-SESSION", tokenData.method());
                filterChain.doFilter(request, response);
                return;
            }
        }

        // No valid token found
        response.sendError(400, "No valid init or recovery token found");
    }
}
