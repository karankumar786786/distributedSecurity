package one.org.security.api.controller.auth;

import one.org.security.core.service.auth.InitSessionService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for InitSessionService in the context of AuthInitController.
 * Tests that init tokens work correctly for the login flow.
 */
@SpringBootTest
@DisplayName("AuthInit Controller Token Tests")
class AuthInitControllerIntegrationTest {

    @Autowired
    private InitSessionService initSessionService;

    private static final String TEST_USER_ID = "507f1f77bcf86cd799439011";
    private static final String TEST_USERNAME = "testuser@example.com";
    private static final String TEST_FLOW_TYPE = "LOGIN-PASSWORD-SESSION";

    @Nested
    @DisplayName("Init Token Generation Tests")
    class InitTokenGenerationTests {

        @Test
        @DisplayName("Should generate valid init token for password login")
        void shouldGenerateValidInitToken() {
            // Given
            String sessionData = "hash|keyId|LOGIN|" + TEST_USER_ID + "|" + TEST_USERNAME;

            // When
            String initToken = initSessionService.generateInitToken(
                    TEST_USER_ID, TEST_USERNAME, TEST_FLOW_TYPE, sessionData);

            // Then
            assertNotNull(initToken, "Init token should not be null");
            assertFalse(initToken.isEmpty(), "Init token should not be empty");
            assertEquals(3, initToken.split("\\.").length, "Token should be valid JWT format");
        }

        @Test
        @DisplayName("Should validate generated init token")
        void shouldValidateGeneratedInitToken() {
            // Given
            String sessionData = "hash|keyId|LOGIN|" + TEST_USER_ID + "|" + TEST_USERNAME;
            String initToken = initSessionService.generateInitToken(
                    TEST_USER_ID, TEST_USERNAME, TEST_FLOW_TYPE, sessionData);

            // When
            InitSessionService.InitTokenData tokenData = initSessionService.validateInitToken(initToken);

            // Then
            assertNotNull(tokenData, "Token data should not be null");
            assertEquals(TEST_USER_ID, tokenData.userId(), "User ID should match");
            assertEquals(TEST_USERNAME, tokenData.username(), "Username should match");
            assertEquals(TEST_FLOW_TYPE, tokenData.flowType(), "Flow type should match");
        }

        @Test
        @DisplayName("Should reject invalid init token")
        void shouldRejectInvalidInitToken() {
            // Given
            String invalidToken = "invalid.token.here";

            // When
            InitSessionService.InitTokenData tokenData = initSessionService.validateInitToken(invalidToken);

            // Then
            assertNull(tokenData, "Invalid token should return null");
        }
    }

    @Nested
    @DisplayName("Token Flow Tests")
    class TokenFlowTests {

        @Test
        @DisplayName("Recovery token should not validate as init token")
        void recoveryTokenShouldNotValidateAsInitToken() {
            // Given
            String recoveryToken = initSessionService.generateRecoveryToken(TEST_USER_ID, "BACKUP_EMAIL");

            // When
            InitSessionService.InitTokenData tokenData = initSessionService.validateInitToken(recoveryToken);

            // Then
            assertNull(tokenData, "Recovery token should not validate as init token");
        }

        @Test
        @DisplayName("Init token should not validate as recovery token")
        void initTokenShouldNotValidateAsRecoveryToken() {
            // Given
            String sessionData = "hash|keyId|LOGIN|" + TEST_USER_ID + "|" + TEST_USERNAME;
            String initToken = initSessionService.generateInitToken(
                    TEST_USER_ID, TEST_USERNAME, TEST_FLOW_TYPE, sessionData);

            // When
            InitSessionService.RecoveryTokenData tokenData = initSessionService.validateRecoveryToken(initToken);

            // Then
            assertNull(tokenData, "Init token should not validate as recovery token");
        }
    }
}
