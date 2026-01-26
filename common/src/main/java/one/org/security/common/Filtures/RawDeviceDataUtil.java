package one.org.security.common.Filtures;

import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class RawDeviceDataUtil {
    public String getRawDeviceHash(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty()) {
            ip = request.getRemoteAddr();
        } else {
            ip = ip.split(",")[0].trim();
        }
        String ua = request.getHeader("User-Agent");
        if (ua == null)
            ua = "unknown";
        ua = ua.replaceAll("[\\r\\n]", "").replaceAll("\\s+", " ").trim();
        return "IP|" + ip + "|UA|" + ua;
    }
}
