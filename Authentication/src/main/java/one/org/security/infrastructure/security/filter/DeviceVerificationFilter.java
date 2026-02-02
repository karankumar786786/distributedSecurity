package one.org.security.infrastructure.security.filter;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import one.org.security.common.Hmac.HmacDTO;
import one.org.security.common.Hmac.HmacService;
import one.org.security.core.service.auth.InitSessionService;
import one.org.security.core.service.auth.InitSessionService.InitTokenData;
import one.org.security.core.service.auth.InitSessionService.RecoveryTokenData;

/**
 * Filter that validates init tokens and recovery tokens from headers.
 * Replaces the cookie-based session verification.
 */
public class DeviceVerificationFilter extends OncePerRequestFilter {

    @Autowired
    private HmacService hmacService;

    @Autowired
    private InitSessionService initSessionService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String rawDeviceBind = (String) request.getAttribute("RAW-DEVICE-BIND");
        String uri = request.getRequestURI();

        // Check for init token in header
        String initToken = request.getHeader("X-Init-Token");

        // Check for recovery token in header
        String recoveryToken = request.getHeader("X-Recovery-Token");

        // Handle login endpoints
        if (uri.equals("/init/login/password")
                || uri.equals("/init/login/password/complete")
                || uri.equals("/init/login/fido")
                || uri.equals("/init/login/fido/complete")) {

            if (initToken == null || initToken.isBlank()) {
                response.sendError(400, "No init token found - provide X-Init-Token header");
                return;
            }

            InitTokenData tokenData = initSessionService.validateInitToken(initToken);
            if (tokenData == null) {
                response.sendError(400, "Invalid or expired init token");
                return;
            }

            // Verify device binding using the HMAC data stored in the token
            String data = tokenData.initData();
            String[] datas = data.split("\\|");
            if (datas.length < 5) {
                response.sendError(400, "Invalid init session format");
                return;
            }

            String hash = datas[0];
            String hashKeyId = datas[1];
            String reason = datas[2];
            String userId = datas[3];
            String username = datas[4];

            String verificationString = rawDeviceBind + reason + userId + username;
            if (!hmacService.verify(new HmacDTO(null, verificationString, hashKeyId, hash))) {
                response.sendError(400, "Invalid device - HMAC verification failed");
                return;
            }

            if (!"LOGIN".equals(reason)) {
                response.sendError(400, "Invalid session reason for login endpoint");
                return;
            }

            request.setAttribute("INIT-SESSION", data);
            request.setAttribute("USERNAME", username);
            request.setAttribute("USER-ID", userId);
            request.setAttribute("USERID", userId);
            request.setAttribute("LOGIN-SESSION", tokenData.flowType());
            filterChain.doFilter(request, response);
            return;

            // Handle forget password endpoints
        } else if (uri.equals("/init/forget-password/backup-email")
                || uri.equals("/init/forget-password/phone-number")) {

            // Initial forget password request needs init token
            if (initToken == null || initToken.isBlank()) {
                response.sendError(400, "No init token found - provide X-Init-Token header");
                return;
            }

            InitTokenData tokenData = initSessionService.validateInitToken(initToken);
            if (tokenData == null) {
                response.sendError(400, "Invalid or expired init token");
                return;
            }

            String data = tokenData.initData();
            String[] datas = data.split("\\|");
            if (datas.length < 5) {
                response.sendError(400, "Invalid init session format");
                return;
            }

            String hash = datas[0];
            String hashKeyId = datas[1];
            String reason = datas[2];
            String userId = datas[3];
            String username = datas[4];

            String verificationString = rawDeviceBind + reason + userId + username;
            if (!hmacService.verify(new HmacDTO(null, verificationString, hashKeyId, hash))) {
                response.sendError(400, "Invalid device");
                return;
            }

            if (!"FORGET_PASSWORD".equals(reason)) {
                response.sendError(400, "Invalid session reason for password recovery");
                return;
            }

            request.setAttribute("INIT-SESSION", data);
            request.setAttribute("USERNAME", username);
            request.setAttribute("USER-ID", userId);
            request.setAttribute("USERID", userId);
            filterChain.doFilter(request, response);
            return;

            // Handle forget password complete/resend endpoints - need recovery token
        } else if (uri.equals("/init/forget-password/backup-email/complete")
                || uri.equals("/init/forget-password/phone-number/complete")
                || uri.equals("/init/forget-password/resend-otp/phone-number")
                || uri.equals("/init/forget-password/resend-otp/backup-email")) {

            if (recoveryToken == null || recoveryToken.isBlank()) {
                response.sendError(400, "No recovery token found - provide X-Recovery-Token header");
                return;
            }

            RecoveryTokenData tokenData = initSessionService.validateRecoveryToken(recoveryToken);
            if (tokenData == null) {
                response.sendError(400, "Invalid or expired recovery token");
                return;
            }

            // Also need init token to get username
            if (initToken == null || initToken.isBlank()) {
                response.sendError(400, "No init token found - provide X-Init-Token header");
                return;
            }

            InitTokenData initData = initSessionService.validateInitToken(initToken);
            if (initData == null) {
                response.sendError(400, "Invalid or expired init token");
                return;
            }

            request.setAttribute("USERNAME", initData.username());
            request.setAttribute("USER-ID", tokenData.userId());
            request.setAttribute("USERID", tokenData.userId());
            request.setAttribute("FORGET-PASSWORD-SESSION", tokenData.method());
            filterChain.doFilter(request, response);
            return;
        }

        response.sendError(400, "Invalid endpoint or missing authentication");
    }
}
