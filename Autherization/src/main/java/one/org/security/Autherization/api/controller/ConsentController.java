package one.org.security.Autherization.api.controller;

import org.springframework.stereotype.Controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;

@Controller
public class ConsentController {

    @org.springframework.beans.factory.annotation.Autowired
    private org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService authorizationService;

    @GetMapping("/oauth2/consent")
    public String consent(@RequestParam java.util.Map<String, String> parameters) {

        System.out
                .println("DEBUG: ConsentController - Redirecting to Frontend Consent Page with params: " + parameters);

        String frontendUrl = "http://localhost:5173/oauth2/consent";

        org.springframework.web.util.UriComponentsBuilder builder = org.springframework.web.util.UriComponentsBuilder
                .fromHttpUrl(frontendUrl);

        // Add all parameters received from the redirect
        parameters.forEach(builder::queryParam);

        // Recover missing parameters (response_type, code_challenge, etc.) from the
        // saved Authorization Request
        String state = parameters.get(org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.STATE);
        if (state != null) {
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization authorization = authorizationService
                    .findByToken(
                            state, new org.springframework.security.oauth2.server.authorization.OAuth2TokenType(
                                    org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.STATE));

            if (authorization != null) {
                org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest authorizationRequest = authorization
                        .getAttribute(
                                org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.class
                                        .getName());

                if (authorizationRequest != null) {
                    System.out.println("DEBUG: ConsentController - Recovered full Authorization Request from State");

                    // Ensure response_type is present
                    if (!parameters.containsKey(
                            org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.RESPONSE_TYPE)) {
                        builder.queryParam(
                                org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.RESPONSE_TYPE,
                                authorizationRequest.getResponseType().getValue());
                    }

                    // Ensure client_id is present (though usually passed)
                    if (!parameters.containsKey(
                            org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CLIENT_ID)) {
                        builder.queryParam(
                                org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CLIENT_ID,
                                authorizationRequest.getClientId());
                    }

                    // Ensure redirect_uri is present
                    if (!parameters.containsKey(
                            org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.REDIRECT_URI)
                            && authorizationRequest.getRedirectUri() != null) {
                        builder.queryParam(
                                org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.REDIRECT_URI,
                                authorizationRequest.getRedirectUri());
                    }

                    // Ensure scopes are present
                    if (!parameters
                            .containsKey(org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.SCOPE)
                            && !authorizationRequest.getScopes().isEmpty()) {
                        builder.queryParam(org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.SCOPE,
                                String.join(" ", authorizationRequest.getScopes()));
                    }

                    // Ensure Code Challenge (PKCE) is present
                    java.util.Map<String, Object> additionalParameters = authorizationRequest.getAdditionalParameters();
                    if (additionalParameters.containsKey(PkceParameterNames.CODE_CHALLENGE)) {
                        builder.queryParam(
                                PkceParameterNames.CODE_CHALLENGE,
                                additionalParameters.get(PkceParameterNames.CODE_CHALLENGE));
                    }
                    if (additionalParameters.containsKey(
                            PkceParameterNames.CODE_CHALLENGE_METHOD)) {
                        builder.queryParam(
                                PkceParameterNames.CODE_CHALLENGE_METHOD,
                                additionalParameters.get(
                                        PkceParameterNames.CODE_CHALLENGE_METHOD));
                    }
                }
            }
        }

        return "redirect:" + builder.build().toUriString();
    }
}
