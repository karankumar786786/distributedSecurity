package one.org.security.common.filter;

import java.io.IOException;
import java.util.Collections;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import one.org.security.common.dto.TokenDTO;
import one.org.security.common.model.AuthenticatedUser;
import one.org.security.common.enums.TokenPurposeMessageEnum;
import one.org.security.common.service.VerifyUserService;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private VerifyUserService verifyUserService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        String rawDeviceData = request.getHeader("RAW_DEVICE_DATA");

        if (authHeader != null && authHeader.startsWith("Bearer ") && rawDeviceData != null) {
            String token = authHeader.substring(7);

            try {
                TokenDTO tokenData = verifyUserService.verifyUser(token, rawDeviceData,
                        TokenPurposeMessageEnum.ACCESS_TOKEN);

                if (tokenData != null) {
                    AuthenticatedUser authenticatedUser = new AuthenticatedUser(tokenData);
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            authenticatedUser, null, authenticatedUser.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (Exception e) {
                // Token verification failed, but we continue the filter chain
                // SecurityContext will be empty, so subsequent security checks will fail if
                // authentication is required
                // logging might be good here
            }
        }

        filterChain.doFilter(request, response);
    }
}
