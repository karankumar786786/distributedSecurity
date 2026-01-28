package one.org.security.common.Filtures;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class ProcessDeviceFilter extends OncePerRequestFilter {
    @Autowired
    private RawDeviceDataUtil rawDeviceDataUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        System.out.println("Processing Device Filter: " + request.getRequestURI());
        String rawDeviceData = rawDeviceDataUtil.getRawDeviceHash(request);
        if (rawDeviceData == null || !rawDeviceData.contains("|")) {
            response.sendError(400, "Device data header missing");
            return;
        }
        String[] parts = rawDeviceData.split("\\|");
        if (parts.length < 4) {
            response.sendError(400, "Device data malformed");
            return;
        }
        ;
        String ipAddress = parts[1];
        String deviceBind = parts[3];
        if ("unknown".equals(deviceBind)) {
            response.sendError(400, "Device identification failed");
            return;
        }
        ;
        request.setAttribute("IP-ADDRESS", ipAddress);
        request.setAttribute("RAW-DEVICE-BIND", deviceBind);
        filterChain.doFilter(request, response);
    }

    
}
