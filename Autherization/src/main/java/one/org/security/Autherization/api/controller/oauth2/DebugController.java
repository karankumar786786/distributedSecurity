package one.org.security.Autherization.api.controller.oauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@Profile("dev")
@Slf4j
public class DebugController {

    @Autowired
    private OAuth2AuthorizationService authorizationService;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @GetMapping("/debug/pkce-test")
    public Map<String, Object> testPkcePersistence() {
        Map<String, Object> results = new HashMap<>();
        try {
            String clientId = "testclient1";
            RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
            if (registeredClient == null) {
                results.put("error", "Client not found: " + clientId);
                return results;
            }

            String state = "debug-state-" + UUID.randomUUID();
            String codeChallenge = "debug-challenge-" + UUID.randomUUID();

            // 1. Create Initial Authorization Request
            OAuth2AuthorizationRequest authRequest = OAuth2AuthorizationRequest.authorizationCode()
                    .authorizationUri("http://localhost:12000/oauth2/authorize")
                    .clientId(clientId)
                    .redirectUri("http://localhost:13000/login/oauth2/code/testclient1")
                    .state(state)
                    .additionalParameters(params -> {
                        params.put("code_challenge", codeChallenge);
                        params.put("code_challenge_method", "S256");
                    })
                    .build();

            // 2. Create and Save Initial Authorization
            OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                    .principalName("debug-user")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .attribute(OAuth2AuthorizationRequest.class.getName(), authRequest)
                    .attribute("state", state)
                    .build();

            authorizationService.save(authorization);
            results.put("step1_save_initial", "SUCCESS");

            // 3. Retrieve by state
            OAuth2Authorization loadedByState = authorizationService.findByToken(state, new OAuth2TokenType("state"));
            if (loadedByState == null) {
                results.put("step2_load_by_state", "FAILED");
                return results;
            }

            OAuth2AuthorizationRequest loadedReq1 = loadedByState
                    .getAttribute(OAuth2AuthorizationRequest.class.getName());
            results.put("step2_pkce_in_loaded_state",
                    loadedReq1 != null ? loadedReq1.getAttribute("code_challenge") : "NULL");

            // 4. Update with Code (Mimic ConsentProcessController)
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                    "debug-code-" + UUID.randomUUID(),
                    Instant.now(),
                    Instant.now().plusSeconds(300));

            OAuth2Authorization updatedAuth = OAuth2Authorization.from(loadedByState)
                    .token(authorizationCode)
                    .build();

            authorizationService.save(updatedAuth);
            results.put("step3_save_updated", "SUCCESS");

            // 5. Retrieve by code
            OAuth2Authorization loadedByCode = authorizationService.findByToken(authorizationCode.getTokenValue(),
                    new OAuth2TokenType("code"));
            if (loadedByCode == null) {
                results.put("step4_load_by_code", "FAILED");
                return results;
            }

            OAuth2AuthorizationRequest loadedReq2 = loadedByCode
                    .getAttribute(OAuth2AuthorizationRequest.class.getName());

            String restoredChallenge = null;
            if (loadedReq2 != null) {
                restoredChallenge = (String) loadedReq2.getAdditionalParameters().get("code_challenge");
                if (restoredChallenge == null) {
                    restoredChallenge = (String) loadedReq2.getAttribute("code_challenge");
                }
            }
            results.put("step4_pkce_restored_final", restoredChallenge != null ? restoredChallenge : "NULL");

            if (codeChallenge.equals(restoredChallenge)) {
                results.put("FINAL_RESULT", "PASSED - PKCE Persisted correctly");
            } else {
                results.put("FINAL_RESULT", "FAILED - PKCE Data Lost");
            }

        } catch (Exception e) {
            results.put("error", e.getMessage());
            log.error("Error in debug controller", e);
        }
        return results;
    }
}
