package one.org.security.infrastructure.security.filter;

import java.io.IOException;

import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import one.org.security.common.dto.TokenDTO;
import one.org.security.common.enums.TokenPurposeMessageEnum;
import one.org.security.core.domain.entity.User;
import one.org.security.core.service.UserService;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(JwtAuthFilter.class);

    @Autowired
    private one.org.security.common.service.VerifyUserService verifyUserService;

    @Autowired
    private UserService userService;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getServletPath();
        return path.equals("/auth/register") ||
                path.equals("/auth/login") ||
                path.equals("/auth/check-user-exist") ||
                path.equals("/auth/forget-password") ||
                path.equals("/auth/verify-forget-password") ||
                path.equals("/auth/resend-otp") ||
                path.equals("/auth/verify-otp");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String rawDeviceData = (String) request.getAttribute("RAW_DEVICE_DATA");
        log.info(rawDeviceData);
        if (authHeader == null || !authHeader.startsWith("Bearer ") || rawDeviceData == null) {
            filterChain.doFilter(request, response);
            return;
        }

        final String token = authHeader.substring(7);
        try {
            TokenDTO tokenData = verifyUserService.verifyUser(token, rawDeviceData,
                    TokenPurposeMessageEnum.ACCESS_TOKEN);

            if (tokenData != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                User user = userService.getUserById(new ObjectId(tokenData.id()));

                if (user != null) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            user,
                            null,
                            user.getAuthorities() // Ensure User implements UserDetails or provides authorities
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {
            log.error(e.getMessage());
            // Log error or let it propagate. If verification fails, we just don't set
            // authentication.
            // SecurityContext will remain empty, and subsequent security filters (if any)
            // will reject if configured.
        }

        filterChain.doFilter(request, response);
    }
}
