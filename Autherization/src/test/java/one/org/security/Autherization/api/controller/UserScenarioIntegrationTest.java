package one.org.security.Autherization.api.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;

import org.bson.types.ObjectId;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import one.org.security.Autherization.core.domain.entity.ClientEntity;
import one.org.security.Autherization.core.service.Client.ClientService;
import one.org.security.Autherization.core.service.Encoding.CustomEncodingService;

@SpringBootTest
@AutoConfigureMockMvc
public class UserScenarioIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ClientService clientService;

    @Autowired
    private CustomEncodingService customEncodingService;

    @Test
    public void testUserScenario() throws Exception {
        // Use the provided JWT token for stateless authentication
        String jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJrYXJhbiIsInVzZXJJZCI6IjY1MWEyYjNjNGQ1ZTZmN2E4YjljMGQxZSIsImlhdCI6MTcxNzU4NDA3NX0.some_signature";

        // 1. Setup Client like the user's "testclient2"
        String clientId = "testclient2";
        String redirectUrl = "http://localhost:13000/login/oauth2/code/testclient2";

        // Ensure clean state for this client if possible, or update it
        ClientEntity existing = clientService.findByClientId(clientId);
        if (existing != null) {
            existing.setRedirectUrl(redirectUrl);
            clientService.saveClient(existing);
        } else {
            ClientEntity client = ClientEntity.builder()
                    .clientId(clientId)
                    .hashedClientSecretHmac(customEncodingService.encode("secret"))
                    .userId(new ObjectId())
                    .redirectUrl(redirectUrl)
                    .writeAllowed(true)
                    .showConsentForm(true)
                    .allowProfile(true)
                    .allowPersonalData(true)
                    .build();
            clientService.saveClient(client);
        }

        // 2. PKCE Setup
        String codeVerifier = "vXMfSzUFGepk8vMBqMm1Dqsn_X9vAy2FT7KE0l53nnw";
        String codeChallenge = generateCodeChallenge(codeVerifier);
        String nonce = "test-nonce-" + UUID.randomUUID().toString();

        // 3. Authorization Request (use full URL format like
        // AuthorizationFlowIntegrationTest)
        String scope = "openid read";
        String authUrl = String.format(
                "http://localhost:12000/oauth2/authorize?response_type=code&client_id=%s&scope=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&nonce=%s&state=some-state",
                clientId, scope, redirectUrl, codeChallenge, nonce);

        mockMvc.perform(get(authUrl)
                .header("Authorization", "Bearer " + jwtToken)
                .header("User-Agent", "IntegrationTestAgent"))
                .andDo(print())
                .andExpect(status().is3xxRedirection()); // Should redirect to consent page
    }

    private String generateCodeChallenge(String codeVerifier) throws Exception {
        byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(bytes, 0, bytes.length);
        byte[] digest = md.digest();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
