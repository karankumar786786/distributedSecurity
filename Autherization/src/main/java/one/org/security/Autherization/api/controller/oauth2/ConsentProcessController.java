package one.org.security.Autherization.api.controller.oauth2;

import jakarta.servlet.http.HttpServletRequest;
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

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Controller
public class ConsentProcessController {

    @Autowired
    private OAuth2AuthorizationService authorizationService;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @PostMapping("/oauth2/authorize/process")
    public String processConsent(
            @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
            @RequestParam(OAuth2ParameterNames.STATE) String state,
            @RequestParam(OAuth2ParameterNames.REDIRECT_URI) String redirectUri,
            @RequestParam(OAuth2ParameterNames.RESPONSE_TYPE) String responseType,
            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
            @RequestParam(value = "user_oauth_approval", required = false) String userApproval,
            @RequestParam(value = OAuth2ParameterNames.SCOPE, required = false) String[] scopes,
            HttpServletRequest request) {

        System.out.println("==============================================");
        System.out.println("DEBUG: ConsentProcessController - Processing consent");
        System.out.println("DEBUG: client_id: " + clientId);
        System.out.println("DEBUG: state: " + state);
        System.out.println("DEBUG: user_oauth_approval: " + userApproval);
        System.out.println("DEBUG: scopes: " + (scopes != null ? String.join(", ", scopes) : "null"));
        System.out.println("==============================================");

        // Check if user denied
        if (!"true".equals(userApproval)) {
            System.out.println("DEBUG: User denied consent");
            return "redirect:" + redirectUri + "?error=access_denied&state=" + state;
        }

        // Get authenticated user
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            System.out.println("DEBUG: User not authenticated");
            return "redirect:" + redirectUri + "?error=access_denied&state=" + state;
        }

        System.out.println("DEBUG: Authenticated user: " + authentication.getName());

        // Get registered client
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            System.out.println("DEBUG: Client not found: " + clientId);
            return "redirect:" + redirectUri + "?error=invalid_client&state=" + state;
        }

        // Build approved scopes
        Set<String> approvedScopes = new HashSet<>();
        if (scopes != null) {
            for (String scope : scopes) {
                approvedScopes.add(scope);
            }
        }

        System.out.println("DEBUG: Approved scopes: " + approvedScopes);

        // Try to find existing authorization by state
        OAuth2Authorization existingAuth = authorizationService.findByToken(state, new OAuth2TokenType("state"));

        if (existingAuth == null) {
            System.out.println("DEBUG: No existing authorization found for state: " + state);
            return "redirect:" + redirectUri + "?error=invalid_request&state=" + state;
        }

        System.out.println("DEBUG: Found existing authorization: " + existingAuth.getId());

        // Generate authorization code
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                UUID.randomUUID().toString(),
                Instant.now(),
                Instant.now().plusSeconds(300) // 5 minutes
        );

        System.out.println("DEBUG: Generated authorization code: " + authorizationCode.getTokenValue());

        // Update authorization with the code and approved scopes
        OAuth2Authorization updatedAuth = OAuth2Authorization.from(existingAuth)
                .token(authorizationCode)
                .authorizedScopes(approvedScopes)
                .build();

        authorizationService.save(updatedAuth);
        System.out.println("DEBUG: Saved authorization with code");

        // Build redirect URL with authorization code
        String redirectUrl = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam(OAuth2ParameterNames.CODE, authorizationCode.getTokenValue())
                .queryParam(OAuth2ParameterNames.STATE, state)
                .build()
                .toUriString();

        System.out.println("DEBUG: Redirecting to: " + redirectUrl);
        System.out.println("==============================================");

        return "redirect:" + redirectUrl;
    }
}
