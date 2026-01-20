package one.org.security.common.security.filter;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import one.org.security.utils.RawDeviceDataUtil;

import org.springframework.stereotype.Component;

@Component
public class RawDeviceDataFilter extends OncePerRequestFilter {
    @Autowired
    private RawDeviceDataUtil rawDeviceDataUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String rawDeviceData = rawDeviceDataUtil.getRawDeviceHash(request);
        request.setAttribute("RAW_DEVICE_DATA", rawDeviceData);
        filterChain.doFilter(request, response);
    }

}
