package one.org.security.client.infrastructure.security;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

@Component
public class HttpCookieOAuth2AuthorizationRequestRepository
        implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    public static final String OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request";
    public static final String REDIRECT_URI_PARAM_COOKIE_NAME = "redirect_uri";
    private static final int cookieExpireSeconds = 180;

    private void logToFile(String message) {
        try (FileWriter fw = new FileWriter("/Users/rahulgupta/Desktop/distributedSecurity/AuthDebug.txt", true);
                PrintWriter pw = new PrintWriter(fw)) {
            pw.println(LocalDateTime.now() + " - [CLIENT] " + message);
        } catch (Exception e) {
        }
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        logToFile("LOADING AUTHORIZATION REQUEST for URI: " + requestUri);

        OAuth2AuthorizationRequest authRequest = CookieUtils
                .getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
                .map(cookie -> CookieUtils.deserialize(cookie, OAuth2AuthorizationRequest.class))
                .orElse(null);

        if (authRequest != null) {
            String paramState = request.getParameter("state");
            logToFile("  Loaded Cookie State:  " + authRequest.getState());
            logToFile("  Request Param State: " + paramState);
            if (paramState != null && !paramState.equals(authRequest.getState())) {
                logToFile("  !!! STATE MISMATCH detected during load !!!");
            }
        } else {
            logToFile("  No authorization request found in cookies for " + requestUri);
        }
        return authRequest;
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request,
            HttpServletResponse response) {
        logToFile("SAVING AUTHORIZATION REQUEST");
        if (authorizationRequest == null) {
            logToFile("  Request is null, deleting cookies");
            CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
            CookieUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME);
            return;
        }

        logToFile("  Client ID: " + authorizationRequest.getClientId());
        logToFile("  State:     " + authorizationRequest.getState());
        logToFile("  Challenge: " + authorizationRequest.getAttribute("code_challenge"));
        logToFile("  Verifier:  " + authorizationRequest.getAttribute("code_verifier"));

        CookieUtils.addCookie(response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME,
                CookieUtils.serialize(authorizationRequest), cookieExpireSeconds);
        String redirectUriAfterLogin = request.getParameter(REDIRECT_URI_PARAM_COOKIE_NAME);
        if (StringUtils.isNotBlank(redirectUriAfterLogin)) {
            logToFile("  Saving redirect URI: " + redirectUriAfterLogin);
            CookieUtils.addCookie(response, REDIRECT_URI_PARAM_COOKIE_NAME, redirectUriAfterLogin, cookieExpireSeconds);
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request,
            HttpServletResponse response) {
        logToFile("REMOVING AUTHORIZATION REQUEST");
        OAuth2AuthorizationRequest authRequest = this.loadAuthorizationRequest(request);
        return authRequest;
    }
}
