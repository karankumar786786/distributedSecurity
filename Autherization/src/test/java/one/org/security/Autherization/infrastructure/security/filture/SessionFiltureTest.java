package one.org.security.Autherization.infrastructure.security.filture;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import one.org.security.Autherization.core.domain.entity.UserMockEntity;
import one.org.security.common.Jwt.JwtDTO;
import one.org.security.common.Jwt.JwtService;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for SessionFilture (Authorization Service).
 * Tests JWT-only stateless authentication via Authorization header.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SessionFilture Tests (Authorization Service)")
class SessionFiltureTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private SessionFilture sessionFilture;

    // Test constants
    private static final String VALID_TOKEN = "valid.jwt.token";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String TEST_USER_ID = "507f1f77bcf86cd799439011";
    private static final String TEST_USERNAME = "testuser@example.com";
    private static final String TEST_URI = "/oauth2/authorize";
    private static final String USER_AGENT = "Mozilla/5.0 Test Agent";

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
    }

    // Helper method to create JwtDTO using the factory method
    private JwtDTO createJwtDTO() {
        return JwtDTO.ofClaims(TEST_USER_ID, TEST_USERNAME, null, null);
    }

    @Nested
    @DisplayName("JWT Authentication Tests")
    class JwtAuthenticationTests {

        @Test
        @DisplayName("Should authenticate with valid JWT token")
        void shouldAuthenticateWithValidJwtToken() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn(TEST_URI);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(USER_AGENT);
            when(request.getHeader("Authorization")).thenReturn(BEARER_PREFIX + VALID_TOKEN);

            JwtDTO jwtDTO = createJwtDTO();
            when(jwtService.validateTokenWithDevice(VALID_TOKEN, USER_AGENT)).thenReturn(jwtDTO);

            // When
            sessionFilture.doFilterInternal(request, response, filterChain);

            // Then
            verify(filterChain).doFilter(request, response);

            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            assertNotNull(auth, "Authentication should be set");
            assertTrue(auth.isAuthenticated(), "Should be authenticated");

            UserMockEntity principal = (UserMockEntity) auth.getPrincipal();
            assertEquals(TEST_USERNAME, principal.getUsername(), "Username should match");
            assertEquals(new ObjectId(TEST_USER_ID), principal.getId(), "User ID should match");
        }

        @Test
        @DisplayName("Should proceed as anonymous when no Authorization header")
        void shouldProceedAsAnonymousWhenNoAuthorizationHeader() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn(TEST_URI);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(USER_AGENT);
            when(request.getHeader("Authorization")).thenReturn(null);

            // When
            sessionFilture.doFilterInternal(request, response, filterChain);

            // Then
            verify(filterChain).doFilter(request, response);

            // Authentication should not be set
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            assertNull(auth, "Authentication should not be set when no token provided");
        }

        @Test
        @DisplayName("Should proceed as anonymous when Authorization header without Bearer prefix")
        void shouldProceedAsAnonymousWhenNoBearerPrefix() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn(TEST_URI);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(USER_AGENT);
            when(request.getHeader("Authorization")).thenReturn("Basic sometoken");

            // When
            sessionFilture.doFilterInternal(request, response, filterChain);

            // Then
            verify(filterChain).doFilter(request, response);
            assertNull(SecurityContextHolder.getContext().getAuthentication());
        }

        @Test
        @DisplayName("Should proceed as anonymous when JWT validation fails")
        void shouldProceedAsAnonymousWhenJwtValidationFails() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn(TEST_URI);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(USER_AGENT);
            when(request.getHeader("Authorization")).thenReturn(BEARER_PREFIX + "invalid.token");
            when(jwtService.validateTokenWithDevice("invalid.token", USER_AGENT)).thenReturn(null);

            // When
            sessionFilture.doFilterInternal(request, response, filterChain);

            // Then
            verify(filterChain).doFilter(request, response);
            assertNull(SecurityContextHolder.getContext().getAuthentication());
        }
    }

    @Nested
    @DisplayName("Device Binding Tests")
    class DeviceBindingTests {

        @Test
        @DisplayName("Should use User-Agent as fallback for device binding")
        void shouldUseUserAgentAsFallback() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn(TEST_URI);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(null);
            when(request.getHeader("User-Agent")).thenReturn(USER_AGENT);
            when(request.getHeader("Authorization")).thenReturn(BEARER_PREFIX + VALID_TOKEN);

            JwtDTO jwtDTO = createJwtDTO();
            when(jwtService.validateTokenWithDevice(VALID_TOKEN, USER_AGENT)).thenReturn(jwtDTO);

            // When
            sessionFilture.doFilterInternal(request, response, filterChain);

            // Then
            verify(jwtService).validateTokenWithDevice(VALID_TOKEN, USER_AGENT);
            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("Should validate without device binding when none available")
        void shouldValidateWithoutDeviceBinding() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn(TEST_URI);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(null);
            when(request.getHeader("User-Agent")).thenReturn(null);
            when(request.getHeader("Authorization")).thenReturn(BEARER_PREFIX + VALID_TOKEN);

            JwtDTO jwtDTO = createJwtDTO();
            when(jwtService.validateToken(VALID_TOKEN)).thenReturn(jwtDTO);

            // When
            sessionFilture.doFilterInternal(request, response, filterChain);

            // Then
            verify(jwtService).validateToken(VALID_TOKEN);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Nested
    @DisplayName("Request Attribute Tests")
    class RequestAttributeTests {

        @Test
        @DisplayName("Should set JWT claims as request attributes")
        void shouldSetJwtClaimsAsRequestAttributes() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn(TEST_URI);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(USER_AGENT);
            when(request.getHeader("Authorization")).thenReturn(BEARER_PREFIX + VALID_TOKEN);

            JwtDTO jwtDTO = createJwtDTO();
            when(jwtService.validateTokenWithDevice(VALID_TOKEN, USER_AGENT)).thenReturn(jwtDTO);

            // When
            sessionFilture.doFilterInternal(request, response, filterChain);

            // Then
            verify(request).setAttribute("JWT_USER_ID", TEST_USER_ID);
            verify(request).setAttribute("JWT_USERNAME", TEST_USERNAME);
        }
    }

    @Nested
    @DisplayName("No Cookie Tests")
    class NoCookieTests {

        @Test
        @DisplayName("Should never read cookies")
        void shouldNeverReadCookies() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn(TEST_URI);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(USER_AGENT);
            when(request.getHeader("Authorization")).thenReturn(BEARER_PREFIX + VALID_TOKEN);

            JwtDTO jwtDTO = createJwtDTO();
            when(jwtService.validateTokenWithDevice(VALID_TOKEN, USER_AGENT)).thenReturn(jwtDTO);

            // When
            sessionFilture.doFilterInternal(request, response, filterChain);

            // Then
            verify(request, never()).getCookies();
        }

        @Test
        @DisplayName("Should never set cookies")
        void shouldNeverSetCookies() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn(TEST_URI);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(USER_AGENT);
            when(request.getHeader("Authorization")).thenReturn(BEARER_PREFIX + VALID_TOKEN);

            JwtDTO jwtDTO = createJwtDTO();
            when(jwtService.validateTokenWithDevice(VALID_TOKEN, USER_AGENT)).thenReturn(jwtDTO);

            // When
            sessionFilture.doFilterInternal(request, response, filterChain);

            // Then
            verify(response, never()).addCookie(any());
            verify(response, never()).addHeader(eq("Set-Cookie"), any());
        }
    }

    @Nested
    @DisplayName("Exception Handling Tests")
    class ExceptionHandlingTests {

        @Test
        @DisplayName("Should continue filter chain on exception")
        void shouldContinueFilterChainOnException() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn(TEST_URI);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenThrow(new RuntimeException("Test exception"));

            // When
            sessionFilture.doFilterInternal(request, response, filterChain);

            // Then
            verify(filterChain).doFilter(request, response);
        }
    }
}
