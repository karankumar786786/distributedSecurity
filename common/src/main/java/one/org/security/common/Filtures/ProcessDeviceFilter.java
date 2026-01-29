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
        System.out.println("DEBUG: ProcessDeviceFilter - RawDeviceData: " + rawDeviceData);

        if (rawDeviceData == null || !rawDeviceData.contains("|")) {
            System.out.println("DEBUG: ProcessDeviceFilter - rawDeviceData missing or invalid format");
            response.sendError(400, "Device data header missing");
            return;
        }

        String[] parts = rawDeviceData.split("\\|");
        if (parts.length < 4) {
            System.out.println("DEBUG: ProcessDeviceFilter - parts length < 4: " + parts.length);
            response.sendError(400, "Device data malformed");
            return;
        }

        String ipAddress = parts[1];
        String deviceBind = parts[3];
        System.out.println("DEBUG: ProcessDeviceFilter - Extracted IP: " + ipAddress + ", UA: " + deviceBind);

        if ("unknown".equals(deviceBind)) {
            System.out.println("DEBUG: ProcessDeviceFilter - UA is unknown");
            response.sendError(400, "Device identification failed");
            return;
        }

        request.setAttribute("IP-ADDRESS", ipAddress);
        request.setAttribute("RAW-DEVICE-BIND", deviceBind);
        filterChain.doFilter(request, response);
    }
}
