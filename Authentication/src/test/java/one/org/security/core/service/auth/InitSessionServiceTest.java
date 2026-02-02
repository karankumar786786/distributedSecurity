package one.org.security.core.service.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for InitSessionService.
 * Tests JWT token generation and validation for stateless authentication flows.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "jwt.secret=test-secret-key-for-jwt-signing-that-is-at-least-32-bytes-long"
})
@DisplayName("InitSessionService Tests")
class InitSessionServiceTest {

    @Autowired
    private InitSessionService initSessionService;

    // Test constants
    private static final String TEST_USER_ID = "507f1f77bcf86cd799439011";
    private static final String TEST_USERNAME = "testuser@example.com";
    private static final String TEST_FLOW_TYPE = "LOGIN-PASSWORD-SESSION";
    private static final String TEST_RECOVERY_METHOD = "BACKUP_EMAIL";

    @Nested
    @DisplayName("Init Token Tests")
    class InitTokenTests {

        @Test
        @DisplayName("Should generate valid init token with all claims")
        void shouldGenerateValidInitToken() {
            // Given
            String sessionData = "hash|keyId|reason|userId|username";

            // When
            String token = initSessionService.generateInitToken(
                    TEST_USER_ID,
                    TEST_USERNAME,
                    TEST_FLOW_TYPE,
                    sessionData);

            // Then
            assertNotNull(token, "Token should not be null");
            assertFalse(token.isEmpty(), "Token should not be empty");
            assertEquals(3, token.split("\\.").length, "Token should have 3 parts (JWT format)");
        }

        @Test
        @DisplayName("Should validate valid init token")
        void shouldValidateValidInitToken() {
            // Given
            String sessionData = "hash|keyId|reason|userId|username";
            String token = initSessionService.generateInitToken(
                    TEST_USER_ID,
                    TEST_USERNAME,
                    TEST_FLOW_TYPE,
                    sessionData);

            // When
            InitSessionService.InitTokenData result = initSessionService.validateInitToken(token);

            // Then
            assertNotNull(result, "Validation result should not be null");
            assertEquals(TEST_USER_ID, result.userId(), "User ID should match");
            assertEquals(TEST_USERNAME, result.username(), "Username should match");
            assertEquals(TEST_FLOW_TYPE, result.flowType(), "Flow type should match");
            assertEquals(sessionData, result.initData(), "Init data should match");
        }

        @Test
        @DisplayName("Should return null for invalid init token")
        void shouldReturnNullForInvalidInitToken() {
            // Given
            String invalidToken = "invalid.token.here";

            // When
            InitSessionService.InitTokenData result = initSessionService.validateInitToken(invalidToken);

            // Then
            assertNull(result, "Validation should return null for invalid token");
        }

        @Test
        @DisplayName("Should return null for null token")
        void shouldReturnNullForNullToken() {
            // When
            InitSessionService.InitTokenData result = initSessionService.validateInitToken(null);

            // Then
            assertNull(result, "Validation should return null for null token");
        }

        @Test
        @DisplayName("Should return null for empty token")
        void shouldReturnNullForEmptyToken() {
            // When
            InitSessionService.InitTokenData result = initSessionService.validateInitToken("");

            // Then
            assertNull(result, "Validation should return null for empty token");
        }

        @Test
        @DisplayName("Should return null for malformed JWT")
        void shouldReturnNullForMalformedJwt() {
            // Given
            String malformedToken = "not.a.valid.jwt.token";

            // When
            InitSessionService.InitTokenData result = initSessionService.validateInitToken(malformedToken);

            // Then
            assertNull(result, "Validation should return null for malformed JWT");
        }
    }

    @Nested
    @DisplayName("Recovery Token Tests")
    class RecoveryTokenTests {

        @Test
        @DisplayName("Should generate valid recovery token")
        void shouldGenerateValidRecoveryToken() {
            // When
            String token = initSessionService.generateRecoveryToken(TEST_USER_ID, TEST_RECOVERY_METHOD);

            // Then
            assertNotNull(token, "Token should not be null");
            assertFalse(token.isEmpty(), "Token should not be empty");
            assertEquals(3, token.split("\\.").length, "Token should have 3 parts (JWT format)");
        }

        @Test
        @DisplayName("Should validate valid recovery token")
        void shouldValidateValidRecoveryToken() {
            // Given
            String token = initSessionService.generateRecoveryToken(TEST_USER_ID, TEST_RECOVERY_METHOD);

            // When
            InitSessionService.RecoveryTokenData result = initSessionService.validateRecoveryToken(token);

            // Then
            assertNotNull(result, "Validation result should not be null");
            assertEquals(TEST_USER_ID, result.userId(), "User ID should match");
            assertEquals(TEST_RECOVERY_METHOD, result.method(), "Recovery method should match");
        }

        @Test
        @DisplayName("Should return null for invalid recovery token")
        void shouldReturnNullForInvalidRecoveryToken() {
            // Given
            String invalidToken = "invalid.recovery.token";

            // When
            InitSessionService.RecoveryTokenData result = initSessionService.validateRecoveryToken(invalidToken);

            // Then
            assertNull(result, "Validation should return null for invalid token");
        }

        @Test
        @DisplayName("Should return null for null recovery token")
        void shouldReturnNullForNullRecoveryToken() {
            // When
            InitSessionService.RecoveryTokenData result = initSessionService.validateRecoveryToken(null);

            // Then
            assertNull(result, "Validation should return null for null token");
        }
    }

    @Nested
    @DisplayName("Token Uniqueness Tests")
    class TokenUniquenessTests {

        @Test
        @DisplayName("Should generate unique tokens for same input at different times")
        void shouldGenerateUniqueTokens() throws InterruptedException {
            // Given
            String sessionData = "hash|keyId|reason|userId|username";

            // When
            String token1 = initSessionService.generateInitToken(
                    TEST_USER_ID, TEST_USERNAME, TEST_FLOW_TYPE, sessionData);

            // Wait for more than 1 second to ensure different iat timestamp
            Thread.sleep(1100);

            String token2 = initSessionService.generateInitToken(
                    TEST_USER_ID, TEST_USERNAME, TEST_FLOW_TYPE, sessionData);

            // Then
            assertNotEquals(token1, token2, "Tokens should be unique due to different timestamps");
        }

        @Test
        @DisplayName("Should generate different tokens for different users")
        void shouldGenerateDifferentTokensForDifferentUsers() {
            // Given
            String sessionData = "hash|keyId|reason|userId|username";

            // When
            String token1 = initSessionService.generateInitToken(
                    TEST_USER_ID, TEST_USERNAME, TEST_FLOW_TYPE, sessionData);
            String token2 = initSessionService.generateInitToken(
                    "differentUserId", "different@example.com", TEST_FLOW_TYPE, sessionData);

            // Then
            assertNotEquals(token1, token2, "Tokens for different users should be different");
        }
    }

    @Nested
    @DisplayName("Cross-Validation Tests")
    class CrossValidationTests {

        @Test
        @DisplayName("Init token should not validate as recovery token")
        void initTokenShouldNotValidateAsRecoveryToken() {
            // Given
            String sessionData = "hash|keyId|reason|userId|username";
            String initToken = initSessionService.generateInitToken(
                    TEST_USER_ID, TEST_USERNAME, TEST_FLOW_TYPE, sessionData);

            // When
            InitSessionService.RecoveryTokenData result = initSessionService.validateRecoveryToken(initToken);

            // Then
            assertNull(result, "Init token should not validate as recovery token");
        }

        @Test
        @DisplayName("Recovery token should not validate as init token")
        void recoveryTokenShouldNotValidateAsInitToken() {
            // Given
            String recoveryToken = initSessionService.generateRecoveryToken(TEST_USER_ID, TEST_RECOVERY_METHOD);

            // When
            InitSessionService.InitTokenData result = initSessionService.validateInitToken(recoveryToken);

            // Then
            assertNull(result, "Recovery token should not validate as init token");
        }
    }
}
