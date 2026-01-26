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

public class ResendOtpVerificationOnAuthFilter extends OncePerRequestFilter {

    @Autowired
    private HmacService hmacService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String rawDeviceBind = (String) request.getAttribute("RAW-DEVICE-BIND");
        Cookie[] cookies = request.getCookies();

        String initSessionData = null;
        String flowSession = null;

        if (cookies != null) {
            for (Cookie c : cookies) {
                if ("INIT-SESSION".equals(c.getName())) {
                    initSessionData = c.getValue();
                } else if ("FORGET-PASSWORD-SESSION".equals(c.getName()) || "LOGIN-SESSION".equals(c.getName())) {
                    flowSession = c.getValue();
                }
            }
        }
        String username = null;
        String deviceHash = null;
        String deviceHashKeyId = null;
        String reason = null;
        String userId = null;
        if (initSessionData != null && flowSession != null) {
            String[] datas = initSessionData.split("\\|");
            if (datas.length < 5) {
                response.sendError(400, "invalid init session format");
                return;
            }
            deviceHash = datas[0];
            deviceHashKeyId = datas[1];
            reason = datas[2];
            userId = datas[3];
            username = datas[4];
        } else {
            response.sendError(400, "no valid session found");
            return;
        }
        if (username == null || userId == null) {
            response.sendError(400, "username not found in session");
            return;
        };
        String veifySessionString = rawDeviceBind+reason+userId+username;
        boolean verify = hmacService.verify(new HmacDTO(null, veifySessionString, deviceHashKeyId, deviceHash));
        if (!verify) {
            response.sendError(400, "invalid device");
            return;
        }

        if (username != null && userId != null) {
            request.setAttribute("USERNAME", username);
            request.setAttribute("USERID", userId);
        }
        filterChain.doFilter(request, response);
    }

}
