package one.org.security.Autherization.infrastructure.security.converter;

import jakarta.servlet.http.HttpServletRequest;
import one.org.security.Autherization.core.domain.entity.UserMockEntity;
import one.org.security.common.Jwt.JwtDTO;
import one.org.security.common.Jwt.JwtService;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for SessionAwareAuthorizationCodeRequestAuthenticationConverter.
 * Tests JWT-only authentication restoration (no cookies).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("SessionAwareAuthorizationCodeRequestAuthenticationConverter Tests")
class SessionAwareAuthorizationCodeRequestAuthenticationConverterTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private HttpServletRequest request;

    private SessionAwareAuthorizationCodeRequestAuthenticationConverter converter;

    // Test constants
    private static final String VALID_TOKEN = "valid.jwt.token";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String TEST_USER_ID = "507f1f77bcf86cd799439011";
    private static final String TEST_USERNAME = "testuser@example.com";
    private static final String USER_AGENT = "Mozilla/5.0 Test Agent";

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        converter = new SessionAwareAuthorizationCodeRequestAuthenticationConverter(jwtService);
    }

    // Helper method to create JwtDTO using the factory method
    private JwtDTO createJwtDTO() {
        return JwtDTO.ofClaims(TEST_USER_ID, TEST_USERNAME, null, null);
    }

    @Nested
    @DisplayName("JWT Authentication Restoration Tests")
    class JwtRestorationTests {

        @Test
        @DisplayName("Should restore authentication from valid JWT token")
        void shouldRestoreAuthenticationFromValidJwt() {
            // Given
            when(request.getHeader("Authorization")).thenReturn(BEARER_PREFIX + VALID_TOKEN);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(USER_AGENT);
            when(request.getParameter("response_type")).thenReturn("code");
            when(request.getParameter("client_id")).thenReturn("test-client");

            JwtDTO jwtDTO = createJwtDTO();
            when(jwtService.validateTokenWithDevice(VALID_TOKEN, USER_AGENT)).thenReturn(jwtDTO);

            // When
            converter.convert(request);

            // Then
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            assertNotNull(auth, "Authentication should be restored");
            assertTrue(auth.isAuthenticated(), "Should be authenticated");

            UserMockEntity principal = (UserMockEntity) auth.getPrincipal();
            assertEquals(TEST_USERNAME, principal.getUsername(), "Username should match");
            assertEquals(new ObjectId(TEST_USER_ID), principal.getId(), "User ID should match");
        }

        @Test
        @DisplayName("Should skip restoration if already authenticated")
        void shouldSkipRestorationIfAlreadyAuthenticated() {
            // Given - Set up existing authentication
            UserMockEntity existingUser = UserMockEntity.builder()
                    .id(new ObjectId())
                    .username("existing@example.com")
                    .build();
            UsernamePasswordAuthenticationToken existingAuth = new UsernamePasswordAuthenticationToken(existingUser,
                    null, existingUser.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(existingAuth);

            when(request.getParameter("response_type")).thenReturn("code");
            when(request.getParameter("client_id")).thenReturn("test-client");

            // When
            converter.convert(request);

            // Then - Should not call JWT service
            verify(jwtService, never()).validateTokenWithDevice(any(), any());
            verify(jwtService, never()).validateToken(any());

            // Original authentication should remain
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            UserMockEntity principal = (UserMockEntity) auth.getPrincipal();
            assertEquals("existing@example.com", principal.getUsername());
        }

        @Test
        @DisplayName("Should restore authentication for anonymous token")
        void shouldRestoreAuthenticationForAnonymousToken() {
            // Given - Set up anonymous authentication
            AnonymousAuthenticationToken anonymousAuth = new AnonymousAuthenticationToken(
                    "key", "anonymous",
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
            SecurityContextHolder.getContext().setAuthentication(anonymousAuth);

            when(request.getHeader("Authorization")).thenReturn(BEARER_PREFIX + VALID_TOKEN);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(USER_AGENT);
            when(request.getParameter("response_type")).thenReturn("code");
            when(request.getParameter("client_id")).thenReturn("test-client");

            JwtDTO jwtDTO = createJwtDTO();
            when(jwtService.validateTokenWithDevice(VALID_TOKEN, USER_AGENT)).thenReturn(jwtDTO);

            // When
            converter.convert(request);

            // Then - Should restore proper authentication
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            assertFalse(auth instanceof AnonymousAuthenticationToken);

            UserMockEntity principal = (UserMockEntity) auth.getPrincipal();
            assertEquals(TEST_USERNAME, principal.getUsername());
        }
    }

    @Nested
    @DisplayName("Missing/Invalid Token Tests")
    class MissingInvalidTokenTests {

        @Test
        @DisplayName("Should not set authentication when no Authorization header")
        void shouldNotSetAuthenticationWhenNoAuthHeader() {
            // Given
            when(request.getHeader("Authorization")).thenReturn(null);
            when(request.getParameter("response_type")).thenReturn("code");
            when(request.getParameter("client_id")).thenReturn("test-client");

            // When
            converter.convert(request);

            // Then
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            assertNull(auth, "Authentication should not be set");
        }

        @Test
        @DisplayName("Should not set authentication when Authorization header without Bearer prefix")
        void shouldNotSetAuthenticationWhenNoBearerPrefix() {
            // Given
            when(request.getHeader("Authorization")).thenReturn("Basic sometoken");
            when(request.getParameter("response_type")).thenReturn("code");
            when(request.getParameter("client_id")).thenReturn("test-client");

            // When
            converter.convert(request);

            // Then
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            assertNull(auth, "Authentication should not be set");
        }

        @Test
        @DisplayName("Should not set authentication when JWT validation fails")
        void shouldNotSetAuthenticationWhenJwtValidationFails() {
            // Given
            when(request.getHeader("Authorization")).thenReturn(BEARER_PREFIX + "invalid.token");
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(USER_AGENT);
            when(request.getParameter("response_type")).thenReturn("code");
            when(request.getParameter("client_id")).thenReturn("test-client");
            when(jwtService.validateTokenWithDevice("invalid.token", USER_AGENT)).thenReturn(null);

            // When
            converter.convert(request);

            // Then
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            assertNull(auth, "Authentication should not be set");
        }
    }

    @Nested
    @DisplayName("Device Binding Tests")
    class DeviceBindingTests {

        @Test
        @DisplayName("Should use User-Agent as fallback for device binding")
        void shouldUseUserAgentAsFallback() {
            // Given
            when(request.getHeader("Authorization")).thenReturn(BEARER_PREFIX + VALID_TOKEN);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(null);
            when(request.getHeader("User-Agent")).thenReturn(USER_AGENT);
            when(request.getParameter("response_type")).thenReturn("code");
            when(request.getParameter("client_id")).thenReturn("test-client");

            JwtDTO jwtDTO = createJwtDTO();
            when(jwtService.validateTokenWithDevice(VALID_TOKEN, USER_AGENT)).thenReturn(jwtDTO);

            // When
            converter.convert(request);

            // Then
            verify(jwtService).validateTokenWithDevice(VALID_TOKEN, USER_AGENT);
        }

        @Test
        @DisplayName("Should validate without device binding when none available")
        void shouldValidateWithoutDeviceBinding() {
            // Given
            when(request.getHeader("Authorization")).thenReturn(BEARER_PREFIX + VALID_TOKEN);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(null);
            when(request.getHeader("User-Agent")).thenReturn(null);
            when(request.getParameter("response_type")).thenReturn("code");
            when(request.getParameter("client_id")).thenReturn("test-client");

            JwtDTO jwtDTO = createJwtDTO();
            when(jwtService.validateToken(VALID_TOKEN)).thenReturn(jwtDTO);

            // When
            converter.convert(request);

            // Then
            verify(jwtService).validateToken(VALID_TOKEN);
        }
    }

    @Nested
    @DisplayName("No Cookie Tests")
    class NoCookieTests {

        @Test
        @DisplayName("Should never read cookies")
        void shouldNeverReadCookies() {
            // Given
            when(request.getHeader("Authorization")).thenReturn(BEARER_PREFIX + VALID_TOKEN);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(USER_AGENT);
            when(request.getParameter("response_type")).thenReturn("code");
            when(request.getParameter("client_id")).thenReturn("test-client");

            JwtDTO jwtDTO = createJwtDTO();
            when(jwtService.validateTokenWithDevice(VALID_TOKEN, USER_AGENT)).thenReturn(jwtDTO);

            // When
            converter.convert(request);

            // Then
            verify(request, never()).getCookies();
        }
    }
}
