package one.org.security.Autherization.core.util;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;

import java.util.HashMap;
import java.util.Map;

public class OAuth2Utils {

    public static Map<String, String> extractPkceParameters(OAuth2Authorization authorization) {
        Map<String, String> params = new HashMap<>();
        if (authorization == null) {
            return params;
        }

        // 1. Try attributes directly (if promoted previously)
        addIfPresent(params, PkceParameterNames.CODE_CHALLENGE,
                authorization.getAttribute(PkceParameterNames.CODE_CHALLENGE));
        addIfPresent(params, PkceParameterNames.CODE_CHALLENGE_METHOD,
                authorization.getAttribute(PkceParameterNames.CODE_CHALLENGE_METHOD));
        addIfPresent(params, PkceParameterNames.CODE_VERIFIER,
                authorization.getAttribute(PkceParameterNames.CODE_VERIFIER));
        addIfPresent(params, "nonce", authorization.getAttribute("nonce"));

        // 2. Try Authorization Request
        OAuth2AuthorizationRequest request = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
        if (request != null) {
            extractFromRequest(params, request);
        }

        return params;
    }

    public static Map<String, String> extractPkceParameters(OAuth2AuthorizationRequest request) {
        Map<String, String> params = new HashMap<>();
        if (request != null) {
            extractFromRequest(params, request);
        }
        return params;
    }

    private static void extractFromRequest(Map<String, String> params, OAuth2AuthorizationRequest request) {
        // Additional Parameters (standard location for PKCE in request)
        Map<String, Object> additionalParams = request.getAdditionalParameters();

        if (!params.containsKey(PkceParameterNames.CODE_CHALLENGE)) {
            addIfPresent(params, PkceParameterNames.CODE_CHALLENGE,
                    additionalParams.get(PkceParameterNames.CODE_CHALLENGE));
        }
        if (!params.containsKey(PkceParameterNames.CODE_CHALLENGE)) { // Fallback to attribute
            addIfPresent(params, PkceParameterNames.CODE_CHALLENGE,
                    request.getAttribute(PkceParameterNames.CODE_CHALLENGE));
        }

        if (!params.containsKey(PkceParameterNames.CODE_CHALLENGE_METHOD)) {
            addIfPresent(params, PkceParameterNames.CODE_CHALLENGE_METHOD,
                    additionalParams.get(PkceParameterNames.CODE_CHALLENGE_METHOD));
        }
        if (!params.containsKey(PkceParameterNames.CODE_CHALLENGE_METHOD)) {
            addIfPresent(params, PkceParameterNames.CODE_CHALLENGE_METHOD,
                    request.getAttribute(PkceParameterNames.CODE_CHALLENGE_METHOD));
        }

        if (!params.containsKey(PkceParameterNames.CODE_VERIFIER)) {
            addIfPresent(params, PkceParameterNames.CODE_VERIFIER,
                    additionalParams.get(PkceParameterNames.CODE_VERIFIER));
        }
        if (!params.containsKey(PkceParameterNames.CODE_VERIFIER)) {
            addIfPresent(params, PkceParameterNames.CODE_VERIFIER,
                    request.getAttribute(PkceParameterNames.CODE_VERIFIER));
        }

        if (!params.containsKey("nonce")) {
            addIfPresent(params, "nonce", additionalParams.get("nonce"));
        }
        if (!params.containsKey("nonce")) {
            addIfPresent(params, "nonce", request.getAttribute("nonce"));
        }
    }

    private static void addIfPresent(Map<String, String> params, String key, Object value) {
        if (value != null && value instanceof String) {
            params.put(key, (String) value);
        }
    }
}
