package one.org.security.infrastructure.security.filter;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import one.org.security.HmacDTO;
import one.org.security.HmacService;

public class DeviceVerificationFilter extends OncePerRequestFilter {

    @Autowired
    private HmacService hmacService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String rawDeviceBind = (String) request.getAttribute("RAW-DEVICE-BIND");
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            response.sendError(400, "no session found");
            return;
        }
        String data = null;
        String loginSession = null;
        String forgetPasswordSession = null;
        for (Cookie c : cookies) {
            String name = c.getName();
            if ("INIT-SESSION".equals(name)) {
                data = c.getValue();
            } else if ("LOGIN-SESSION".equals(name)) {
                loginSession = c.getValue();
            } else if ("FORGET-PASSWORD-SESSION".equals(name)) {
                forgetPasswordSession = c.getValue();
            }
        }

        if (data == null) {
            response.sendError(400, "no session found");
            return;
        }

        String[] datas = data.split("\\|");
        if (datas.length < 5) {
            response.sendError(400, "no session found");
            return;
        }

        String hash = datas[0];
        String hashKeyId = datas[1];
        String reason = datas[2];
        String userId = datas[3];
        String username = datas[4];

        String verificationString = rawDeviceBind+ reason + userId + username;
        if (!hmacService.verify(new HmacDTO(null, verificationString, hash, hashKeyId))) {
            response.sendError(400, "invalid session data or device");
            return;
        }

        String uri = request.getRequestURI();

        if (uri.equals("/init/login/password")
                || uri.equals("/init/login/password/complete")
                || uri.equals("/init/login/fido")
                || uri.equals("/init/login/fido/complete")) {

            if ("LOGIN".equals(reason)) {
                if (uri.equals("/init/login/password/complete") || uri.equals("/init/login/fido/complete")) {
                    if (loginSession == null || loginSession.isBlank()) {
                        response.sendError(400, "invalid session");
                        return;
                    }
                    request.setAttribute("LOGIN-SESSION", loginSession);
                }
                request.setAttribute("INIT-SESSION", data);
                request.setAttribute("USERNAME", username);
                request.setAttribute("USERID", userId);
                filterChain.doFilter(request, response);
                return;
            }

        } else if (uri.equals("/init/forget-password/backup-email")
                || uri.equals("/init/forget-password/backup-email/complete")
                || uri.equals("/init/forget-password/phone-number")
                || uri.equals("/init/forget-password/phone-number/complete")
                || uri.equals("/init/forget-password/resend-otp/phone-number")
                || uri.equals("/init/forget-password/resend-otp/backup-email")) {
            if ("FORGET_PASSWORD".equals(reason)) {
                if (uri.equals("/init/forget-password/backup-email/complete")
                        || uri.equals("/init/forget-password/phone-number/complete")
                        || uri.equals("/init/forget-password/resend-otp/phone-number")
                        || uri.equals("/init/forget-password/resend-otp/backup-email")) {
                    if (forgetPasswordSession == null || forgetPasswordSession.isBlank()) {
                        response.sendError(400, "invalid session");
                        return;
                    }
                    request.setAttribute("FORGET-PASSWORD-SESSION", forgetPasswordSession);
                }
                request.setAttribute("INIT-SESSION", data);
                request.setAttribute("USERNAME", username);
                request.setAttribute("USERID", userId);
                filterChain.doFilter(request, response);
                return;
            }
        }

        response.sendError(400, "invalid device exception or in correct api call");
    }

}
