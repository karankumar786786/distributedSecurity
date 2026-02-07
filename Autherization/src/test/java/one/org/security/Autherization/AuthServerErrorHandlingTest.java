package one.org.security.Autherization;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.springframework.boot.test.mock.mockito.MockBean;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import one.org.security.Autherization.core.service.Client.ClientService;
import one.org.security.Autherization.core.domain.entity.ClientEntity;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.BeforeEach;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;

import one.org.security.Autherization.core.service.Encoding.HmacEncodingService;

@SpringBootTest
@AutoConfigureMockMvc
public class AuthServerErrorHandlingTest {

        @Autowired
        private MockMvc mockMvc;

        @MockBean
        private ClientService clientService;

        @MockBean
        private HmacEncodingService hmacEncodingService;

        @Autowired
        private RegisteredClientRepository registeredClientRepository;

        @Autowired
        private OAuth2AuthorizationService authorizationService;

        @BeforeEach
        void setUp() {
                ClientEntity mockClient = new ClientEntity(
                                new ObjectId(),
                                new ObjectId(),
                                "client",
                                "{noop}secret", // Use simple password encoder for test or match existing encoder
                                                // expectations
                                "http://localhost:3000/callback",
                                true,
                                true,
                                true,
                                true);
                // Ensure the mock returns the client when looked up by clientId
                when(clientService.findByClientId("client")).thenReturn(mockClient);

                // Mock HMAC verification to only return true for correct secret
                when(hmacEncodingService.verify(anyString(), anyString())).thenReturn(false);
                when(hmacEncodingService.verify(anyString(), eq("secret"))).thenReturn(true);
        }

        @Test
        void testInvalidClientId() throws Exception {
                mockMvc.perform(get("/oauth2/authorize")
                                .param("response_type", "code")
                                .param("client_id", "invalid_client_id")
                                .param("redirect_uri", "http://localhost:3000/callback")
                                .param("scope", "openid"))
                                .andExpect(status().isBadRequest());
        }

        @Test
        void testInvalidClientSecret() throws Exception {
                mockMvc.perform(post("/oauth2/token")
                                .param("grant_type", "authorization_code")
                                .param("code", "some-valid-code")
                                .param("redirect_uri", "http://localhost:3000/callback")
                                .header("Authorization", "Basic Y2xpZW50Ondyb25nX3NlY3JldA==")) // client:wrong_secret
                                                                                                // in Base64
                                .andExpect(status().isUnauthorized());
        }

        @Test
        void testInvalidRedirectUri() throws Exception {
                mockMvc.perform(get("/oauth2/authorize")
                                .param("response_type", "code")
                                .param("client_id", "client")
                                .param("redirect_uri", "http://invalid-uri.com")
                                .param("scope", "openid"))
                                .andExpect(status().isBadRequest());
        }

        @Test
        void testInvalidScope() throws Exception {
                mockMvc.perform(get("/oauth2/authorize")
                                .param("response_type", "code")
                                .param("client_id", "client")
                                .param("redirect_uri", "http://localhost:3000/callback")
                                .param("scope", "invalid_scope"))
                                .andExpect(status().isBadRequest());
        }

        @Test
        void testMissingCodeChallenge() throws Exception {
                // public clients require PKCE -> expecting error if code_challenge is missing
                mockMvc.perform(get("/oauth2/authorize")
                                .param("response_type", "code")
                                .param("client_id", "client")
                                .param("redirect_uri", "http://localhost:3000/callback")
                                .param("scope", "openid"))
                                // .param("code_challenge", "challenge") // Intentionally omitted
                                // .param("code_challenge_method", "S256")
                                .andDo(print())
                                .andExpect(status().isBadRequest());
                // Expect error: invalid_request, error_description: OAuth 2.0 Parameter:
                // code_challenge
        }

        @Test
        void testInvalidCodeVerifier() throws Exception {
                // 1. Create a RegisteredClient (retrieved via mock repository)
                RegisteredClient registeredClient = registeredClientRepository.findByClientId("client");

                // 2. Create an OAuth2Authorization with a code and code_challenge
                OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                                .withRegisteredClient(registeredClient);

                // 3. Attempt to exchange code with WRONG verifier

                authorizationBuilder.attribute("code_challenge", "valid_challenge_S256");
                authorizationBuilder.attribute("code_challenge_method", "plain");
                authorizationBuilder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
                authorizationBuilder.principalName("user");

                // Add Authorization Code
                OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                                "valid-auth-code",
                                Instant.now(),
                                Instant.now().plus(5, ChronoUnit.MINUTES));
                authorizationBuilder.token(authorizationCode, metadata -> {
                });

                // Add Attributes required
                authorizationBuilder.attribute(
                                "org.springframework.security.oauth2.server.authorization.OAuth2Authorization.AUTHORIZED_SCOPE",
                                Collections.singleton("openid"));

                OAuth2Authorization authorization = authorizationBuilder.build();
                authorizationService.save(authorization);

                // 3. Attempt to exchange code with WRONG verifier
                mockMvc.perform(post("/oauth2/token")
                                .param("grant_type", "authorization_code")
                                .param("code", "valid-auth-code")
                                .param("redirect_uri", "http://localhost:3000/callback")
                                .param("code_verifier", "wrong_verifier") // <--- Incorrect verifier
                                .header("Authorization", "Basic Y2xpZW50OnNlY3JldA==")) // client:secret
                                .andExpect(status().isBadRequest()); // Expect 400 Bad Request (invalid_grant)
        }

        @Test
        void testUnsupportedGrantType() throws Exception {
                mockMvc.perform(post("/oauth2/token")
                                .param("grant_type", "invalid_grant_type")
                                .param("code", "some-valid-code")
                                .param("redirect_uri", "http://localhost:3000/callback")
                                .header("Authorization", "Basic Y2xpZW50OnNlY3JldA=="))
                                .andExpect(status().isBadRequest());
        }

        @Test
        void testExpiredAuthorizationCode() throws Exception {
                RegisteredClient registeredClient = registeredClientRepository.findByClientId("client");
                OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                                .withRegisteredClient(registeredClient);

                authorizationBuilder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
                authorizationBuilder.principalName("user");

                // Add Expired Authorization Code
                OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                                "expired-code",
                                Instant.now().minus(10, ChronoUnit.MINUTES),
                                Instant.now().minus(5, ChronoUnit.MINUTES));
                authorizationBuilder.token(authorizationCode, metadata -> {
                });

                OAuth2Authorization authorization = authorizationBuilder.build();
                authorizationService.save(authorization);

                mockMvc.perform(post("/oauth2/token")
                                .param("grant_type", "authorization_code")
                                .param("code", "expired-code")
                                .param("redirect_uri", "http://localhost:3000/callback")
                                .header("Authorization", "Basic Y2xpZW50OnNlY3JldA=="))
                                .andExpect(status().isBadRequest());
        }

        @Test
        void testMutatedAuthorizationCode() throws Exception {
                RegisteredClient registeredClient = registeredClientRepository.findByClientId("client");
                OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                                .withRegisteredClient(registeredClient);
                authorizationBuilder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
                authorizationBuilder.principalName("user");

                OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                                "original-code",
                                Instant.now(),
                                Instant.now().plus(5, ChronoUnit.MINUTES));
                authorizationBuilder.token(authorizationCode, metadata -> {
                });
                OAuth2Authorization authorization = authorizationBuilder.build();
                authorizationService.save(authorization);

                mockMvc.perform(post("/oauth2/token")
                                .param("grant_type", "authorization_code")
                                .param("code", "original-code-tampered")
                                .param("redirect_uri", "http://localhost:3000/callback")
                                .header("Authorization", "Basic Y2xpZW50OnNlY3JldA=="))
                                .andExpect(status().isBadRequest()); // Expect 400 invalid_grant (code not found)
        }

        @Test
        void testCodeChallengeMethodMismatch() throws Exception {
                // Create client and authorization with S256 challenge
                RegisteredClient registeredClient = registeredClientRepository.findByClientId("client");
                OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                                .withRegisteredClient(registeredClient);
                authorizationBuilder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
                authorizationBuilder.principalName("user");

                // Explicitly set attributes for the PKCE
                authorizationBuilder.attribute("code_challenge_method", "S256");
                authorizationBuilder.attribute("code_challenge", "some-s256-hash-value");

                OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                                "s256-code",
                                Instant.now(),
                                Instant.now().plus(5, ChronoUnit.MINUTES));
                authorizationBuilder.token(authorizationCode, metadata -> {
                });

                OAuth2Authorization authorization = authorizationBuilder.build();
                authorizationService.save(authorization);

                // Attempt to exchange using a verifier that would match "plain" logic (verifier
                // == challenge)
                // but the server expects S256 transformation.
                mockMvc.perform(post("/oauth2/token")
                                .param("grant_type", "authorization_code")
                                .param("code", "s256-code")
                                .param("code_verifier", "some-s256-hash-value")
                                .param("redirect_uri", "http://localhost:3000/callback")
                                .header("Authorization", "Basic Y2xpZW50OnNlY3JldA=="))
                                .andExpect(status().isBadRequest());
        }

        @Test
        void testConfidentialClientMissingSecret() throws Exception {
                // A confidential client (like "client") MUST provide authentication (secret)
                // If it tries to exchange code without "Authorization" header or matching
                // secret, it should fail.
                mockMvc.perform(post("/oauth2/token")
                                .param("grant_type", "authorization_code")
                                .param("code", "some-valid-code")
                                .param("client_id", "client")
                                .param("code_verifier", "verifier")
                                .param("redirect_uri", "http://localhost:3000/callback"))
                                // No Authorization Header
                                .andExpect(status().isUnauthorized());
        }
}
