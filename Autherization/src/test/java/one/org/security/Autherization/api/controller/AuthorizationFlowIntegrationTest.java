package one.org.security.Autherization.api.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import one.org.security.Autherization.test.security.WithMockCustomUser;

import org.springframework.context.annotation.Import;
import one.org.security.Autherization.infrastructure.persistance.CustomRegisteredClientRepository;

@SpringBootTest
@AutoConfigureMockMvc
@Import(CustomRegisteredClientRepository.class)
public class AuthorizationFlowIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private org.springframework.context.ApplicationContext applicationContext;

    @Autowired
    private CustomRegisteredClientRepository customRepo;

    @Autowired
    private org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings authorizationServerSettings;

    @Test
    public void debugBeans() {
        String[] names = applicationContext.getBeanNamesForType(
                org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository.class);
        System.out.println("DEBUG: RegisteredClientRepositories: " + java.util.Arrays.toString(names));
        System.out.println("DEBUG: Auth Server Issuer: " + authorizationServerSettings.getIssuer());
    }

    @Test
    @WithMockCustomUser(username = "karan", userId = "651a2b3c4d5e6f7a8b9c0d1e")
    public void testFullAuthorizationCodeFlow() throws Exception {
        // 1. Create Client
        String redirectUrl = "http://localhost:6000/callback";
        String clientId = "test-integration-client-" + UUID.randomUUID().toString();

        String createClientJson = String.format(
                "{\"clientId\": \"%s\", \"redirectUrl\": \"%s\", \"personalDataAccess\": true, \"profile\": true, \"write\": true}",
                clientId, redirectUrl);

        MvcResult createClientResult = mockMvc.perform(post("/client/create-client")
                .header("User-Agent", "IntegrationTestAgent")
                .contentType(MediaType.APPLICATION_JSON)
                .content(createClientJson))
                .andExpect(status().isCreated())
                .andReturn();

        JsonNode clientResponse = objectMapper.readTree(createClientResult.getResponse().getContentAsString());
        String clientSecret = clientResponse.get("clientSecret").asText();
        System.out.println("Created Client: " + clientId + ", Secret: " + clientSecret);

        // DEBUG: Verify Repo Direct Call
        System.out.println("DEBUG: Calling customRepo.findByClientId(" + clientId + ")");
        org.springframework.security.oauth2.server.authorization.client.RegisteredClient directClient = customRepo
                .findByClientId(clientId);
        if (directClient != null) {
            System.out.println(
                    "DEBUG: Direct Repo Call FOUND client. Grant Types: " + directClient.getAuthorizationGrantTypes());
        } else {
            System.out.println("DEBUG: Direct Repo Call NOT FOUND");
        }

        // 2. PKCE Setup
        String codeVerifier = "vXMfSzUFGepk8vMBqMm1Dqsn_X9vAy2FT7KE0l53nnw"; // High entropy string
        String codeChallenge = generateCodeChallenge(codeVerifier);

        // 3. Authorization Request
        String scope = "read";
        String authUrl = String.format(
                "http://localhost:12000/oauth2/authorize?response_type=code&client_id=%s&scope=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256",
                clientId, scope, redirectUrl, codeChallenge);

        MvcResult authResult = mockMvc.perform(get(authUrl)
                .header("User-Agent", "IntegrationTestAgent"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String location = authResult.getResponse().getHeader("Location");
        System.out.println("Redirect Location: " + location);

        // 3a. Handle Consent Step (If redirected to Consent Page)
        String code = null;
        if (location.contains("/oauth2/consent")) {
            System.out.println("DEBUG: Redirected to Consent Page. Submitting Consent...");
            URI consentUri = new URI(location);
            String consentQuery = consentUri.getQuery();
            String state = null;
            for (String param : consentQuery.split("&")) {
                String[] pair = param.split("=");
                if (pair[0].equals("state")) {
                    // split("=") removes trailing empty strings, so if value ends with =, it gets
                    // truncated
                    // URI.getQuery() returns decoded value, so we don't need to decode again if
                    // it's already decoded
                    // However, to be safe and robust:
                    state = param.substring("state=".length());
                    // If it was still encoded, decode it. But URI.getQuery() is decoded.
                    // Wait, if URI.getQuery() is decoded, state is "abc=".
                    // If we decode "abc=", it stays "abc=".
                    // We just need to capture the full string.
                    break;
                }
            }

            if (state == null) {
                throw new RuntimeException("State not found in consent redirect");
            }

            // Submit Consent
            // Submit Consent - Use Manual Body to avoid encoding issues
            String postBody = "client_id=" + clientId +
                    "&state=" + java.net.URLEncoder.encode(state, StandardCharsets.UTF_8) +
                    "&scope=" + scope +
                    "&consent_action=approve";

            MvcResult consentResult = mockMvc.perform(post("http://localhost:12000/oauth2/authorize")
                    .header("User-Agent", "IntegrationTestAgent")
                    .content(postBody)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                    .andExpect(status().is3xxRedirection())
                    .andReturn();

            location = consentResult.getResponse().getHeader("Location");
            System.out.println("Consent Redirect Location: " + location);
        }

        // Extract code from location (Callback URL)
        // Location will be http://localhost:6000/callback?code=...&state=...
        URI uri = new URI(location);
        String query = uri.getQuery();
        for (String param : query.split("&")) {
            String[] pair = param.split("=");
            if (pair[0].equals("code")) {
                code = pair[1];
                break;
            }
        }

        if (code == null) {
            throw new RuntimeException("Authorization code not found in redirect: " + location);
        }
        System.out.println("Auth Code: " + code);

        // 4. Token Exchange
        mockMvc.perform(post("http://localhost:12000/oauth2/token")
                .header("User-Agent", "IntegrationTestAgent")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", code)
                .param("client_id", clientId)
                .param("client_secret", clientSecret)
                .param("redirect_uri", redirectUrl)
                .param("code_verifier", codeVerifier))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.token_type").value("Bearer"));

        // Test Introspection (Optional, verifies token works)
        // Would need separate request with basic auth or bearer
    }

    private String generateCodeChallenge(String codeVerifier) throws Exception {
        byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(bytes, 0, bytes.length);
        byte[] digest = md.digest();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
