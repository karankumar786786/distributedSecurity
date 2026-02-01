package one.org.security.client.infrastructure.security;

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

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        System.out.println("=== LOADING AUTHORIZATION REQUEST ===");
        System.out.println("Request URI: " + request.getRequestURI());
        OAuth2AuthorizationRequest authRequest = CookieUtils
                .getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
                .map(cookie -> {
                    System.out.println("Found authorization request cookie");
                    return CookieUtils.deserialize(cookie, OAuth2AuthorizationRequest.class);
                })
                .orElse(null);
        if (authRequest != null) {
            System.out.println("Loaded authorization request: " + authRequest.getAuthorizationUri());
        } else {
            System.out.println("No authorization request found in cookies");
        }
        return authRequest;
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request,
            HttpServletResponse response) {
        System.out.println("=== SAVING AUTHORIZATION REQUEST ===");
        if (authorizationRequest == null) {
            System.out.println("Authorization request is null, deleting cookies");
            CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
            CookieUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME);
            return;
        }

        System.out.println("Saving authorization request to cookie");
        System.out.println("Authorization URI: " + authorizationRequest.getAuthorizationUri());
        System.out.println("Client ID: " + authorizationRequest.getClientId());
        CookieUtils.addCookie(response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME,
                CookieUtils.serialize(authorizationRequest), cookieExpireSeconds);
        String redirectUriAfterLogin = request.getParameter(REDIRECT_URI_PARAM_COOKIE_NAME);
        if (StringUtils.isNotBlank(redirectUriAfterLogin)) {
            System.out.println("Saving redirect URI: " + redirectUriAfterLogin);
            CookieUtils.addCookie(response, REDIRECT_URI_PARAM_COOKIE_NAME, redirectUriAfterLogin, cookieExpireSeconds);
        }
        System.out.println("=== AUTHORIZATION REQUEST SAVED ===");
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request,
            HttpServletResponse response) {
        System.out.println("=== REMOVING AUTHORIZATION REQUEST ===");
        OAuth2AuthorizationRequest authRequest = this.loadAuthorizationRequest(request);
        System.out.println(
                "Removed authorization request: " + (authRequest != null ? authRequest.getAuthorizationUri() : "null"));
        return authRequest;
    }
}
