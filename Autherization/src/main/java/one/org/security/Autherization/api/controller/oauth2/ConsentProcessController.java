package one.org.security.Autherization.api.controller.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

import one.org.security.Autherization.core.util.OAuth2Utils;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;

import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Controller
public class ConsentProcessController {

    @Autowired
    private OAuth2AuthorizationService authorizationService;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @PostMapping("/oauth2/authorize/process")
    public String processConsent(
            @RequestParam(value = OAuth2ParameterNames.CLIENT_ID, required = false) String clientId,
            @RequestParam(OAuth2ParameterNames.STATE) String state,
            @RequestParam(value = OAuth2ParameterNames.REDIRECT_URI, required = false) String redirectUri,
            @RequestParam(value = OAuth2ParameterNames.RESPONSE_TYPE, required = false) String responseType,
            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
            @RequestParam(value = "user_oauth_approval", required = false) String userApproval,
            @RequestParam(value = OAuth2ParameterNames.SCOPE, required = false) String[] scopes,
            HttpServletRequest request) {

        log.debug("DEBUG: ConsentProcessController - Processing consent");
        log.debug("DEBUG: client_id: {}", clientId);
        log.debug("DEBUG: state: {}", state);
        log.debug("DEBUG: user_oauth_approval: {}", userApproval);
        log.debug("DEBUG: scopes: {}", (scopes != null ? String.join(", ", scopes) : "null"));

        // Check if user denied
        if (!"true".equals(userApproval)) {
            log.warn("DEBUG: User denied consent");
            return "redirect:" + redirectUri + "?error=access_denied&state=" + state;
        }

        // Get authenticated user
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            log.warn("DEBUG: User not authenticated");
            return "redirect:" + redirectUri + "?error=access_denied&state=" + state;
        }

        log.debug("DEBUG: Authenticated user: {}", authentication.getName());

        // Get registered client
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            log.error("DEBUG: Client not found: {}", clientId);
            return "redirect:" + redirectUri + "?error=invalid_client&state=" + state;
        }

        // Build approved scopes
        Set<String> approvedScopes = new HashSet<>();
        if (scopes != null) {
            for (String scope : scopes) {
                approvedScopes.add(scope);
            }
        }

        log.debug("DEBUG: Approved scopes: {}", approvedScopes);

        // Try to find existing authorization by state
        OAuth2Authorization existingAuth = authorizationService.findByToken(state, new OAuth2TokenType("state"));

        if (existingAuth == null) {
            log.warn("DEBUG: No existing authorization found for state: {}", state);
            return "redirect:" + redirectUri + "?error=invalid_request&state=" + state;
        }

        log.debug("DEBUG: Found existing authorization: {}", existingAuth.getId());

        // Recover missing parameters from the saved authorization request if needed
        org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest authorizationRequest = existingAuth
                .getAttribute(
                        org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.class.getName());

        if (authorizationRequest != null) {
            if (clientId == null)
                clientId = authorizationRequest.getClientId();
            if (redirectUri == null)
                redirectUri = authorizationRequest.getRedirectUri();
            if (responseType == null)
                responseType = authorizationRequest.getResponseType().getValue();

            Map<String, String> pkceParams = OAuth2Utils.extractPkceParameters(existingAuth);
            if (codeChallenge == null) {
                codeChallenge = pkceParams.get(PkceParameterNames.CODE_CHALLENGE);
            }
            if (codeChallengeMethod == null) {
                codeChallengeMethod = pkceParams.get(PkceParameterNames.CODE_CHALLENGE_METHOD);
            }

            log.debug("DEBUG: Recovered parameters from Authorization");
            log.debug("DEBUG: Recovered client_id: {}", clientId);
            log.debug("DEBUG: Recovered redirect_uri: {}", redirectUri);
        }

        if (redirectUri == null) {
            log.error("DEBUG: ERROR - Missing redirect_uri and could not recover from Authorization");
            return "error"; // Should probably have a better error page
        }

        // Generate authorization code
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                UUID.randomUUID().toString(),
                Instant.now(),
                Instant.now().plusSeconds(300) // 5 minutes
        );

        log.debug("DEBUG: Generated authorization code: {}", authorizationCode.getTokenValue());

        // Update authorization with the code and approved scopes
        OAuth2Authorization updatedAuth = OAuth2Authorization.from(existingAuth)
                .token(authorizationCode)
                .authorizedScopes(approvedScopes)
                .build();

        authorizationService.save(updatedAuth);
        log.info("DEBUG: Saved authorization with code");

        // Use the original client state for the redirect back to the client
        String finalState = (String) existingAuth.getAttribute("client_state");
        if (finalState == null) {
            finalState = state; // Fallback to whatever we have
        }

        // Build redirect URL with authorization code
        String redirectUrl = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam(OAuth2ParameterNames.CODE, authorizationCode.getTokenValue())
                .queryParam(OAuth2ParameterNames.STATE, finalState)
                .build()
                .toUriString();

        log.info("DEBUG: Redirecting to: {}", redirectUrl);

        return "redirect:" + redirectUrl;
    }
}
