package one.org.security.infrastructure.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import one.org.security.common.Jwt.JwtDTO;
import one.org.security.common.Jwt.JwtService;
import one.org.security.core.domain.entity.User;
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
 * Unit tests for SessionFilter.
 * Tests JWT-only stateless authentication via Authorization header.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SessionFilter Tests")
class SessionFilterTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private SessionFilter sessionFilter;

    // Test constants
    private static final String VALID_TOKEN = "valid.jwt.token";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String TEST_USER_ID = "507f1f77bcf86cd799439011";
    private static final String TEST_USERNAME = "testuser@example.com";
    private static final String TEST_URI = "/api/test";
    private static final String USER_AGENT = "Mozilla/5.0 Test Agent";

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
    }

    // Helper method to create JwtDTO using the ofClaims factory method
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
            sessionFilter.doFilterInternal(request, response, filterChain);

            // Then
            verify(filterChain).doFilter(request, response);

            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            assertNotNull(auth, "Authentication should be set");
            assertTrue(auth.isAuthenticated(), "Should be authenticated");

            User principal = (User) auth.getPrincipal();
            assertEquals(TEST_USERNAME, principal.getUsername(), "Username should match");
        }

        @Test
        @DisplayName("Should authenticate without device binding if none provided")
        void shouldAuthenticateWithoutDeviceBinding() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn(TEST_URI);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(null);
            when(request.getHeader("User-Agent")).thenReturn(null);
            when(request.getHeader("Authorization")).thenReturn(BEARER_PREFIX + VALID_TOKEN);

            JwtDTO jwtDTO = createJwtDTO();
            when(jwtService.validateToken(VALID_TOKEN)).thenReturn(jwtDTO);

            // When
            sessionFilter.doFilterInternal(request, response, filterChain);

            // Then
            verify(filterChain).doFilter(request, response);
            verify(jwtService).validateToken(VALID_TOKEN);
        }

        @Test
        @DisplayName("Should fallback to User-Agent when RAW-DEVICE-BIND is null")
        void shouldFallbackToUserAgent() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn(TEST_URI);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(null);
            when(request.getHeader("User-Agent")).thenReturn(USER_AGENT);
            when(request.getHeader("Authorization")).thenReturn(BEARER_PREFIX + VALID_TOKEN);

            JwtDTO jwtDTO = createJwtDTO();
            when(jwtService.validateTokenWithDevice(VALID_TOKEN, USER_AGENT)).thenReturn(jwtDTO);

            // When
            sessionFilter.doFilterInternal(request, response, filterChain);

            // Then
            verify(filterChain).doFilter(request, response);
            verify(jwtService).validateTokenWithDevice(VALID_TOKEN, USER_AGENT);
        }
    }

    @Nested
    @DisplayName("Missing/Invalid Token Tests")
    class MissingInvalidTokenTests {

        @Test
        @DisplayName("Should return 401 when no Authorization header")
        void shouldReturn401WhenNoAuthorizationHeader() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn(TEST_URI);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(USER_AGENT);
            when(request.getHeader("Authorization")).thenReturn(null);

            // When
            sessionFilter.doFilterInternal(request, response, filterChain);

            // Then
            verify(response).sendError(eq(401), anyString());
            verify(filterChain, never()).doFilter(any(), any());
        }

        @Test
        @DisplayName("Should return 401 when Authorization header without Bearer prefix")
        void shouldReturn401WhenAuthorizationWithoutBearerPrefix() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn(TEST_URI);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(USER_AGENT);
            when(request.getHeader("Authorization")).thenReturn("Basic sometoken");

            // When
            sessionFilter.doFilterInternal(request, response, filterChain);

            // Then
            verify(response).sendError(eq(401), anyString());
            verify(filterChain, never()).doFilter(any(), any());
        }

        @Test
        @DisplayName("Should return 401 when JWT validation fails")
        void shouldReturn401WhenJwtValidationFails() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn(TEST_URI);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenReturn(USER_AGENT);
            when(request.getHeader("Authorization")).thenReturn(BEARER_PREFIX + "invalid.token");
            when(jwtService.validateTokenWithDevice("invalid.token", USER_AGENT)).thenReturn(null);

            // When
            sessionFilter.doFilterInternal(request, response, filterChain);

            // Then
            verify(response).sendError(eq(401), anyString());
            verify(filterChain, never()).doFilter(any(), any());
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
            sessionFilter.doFilterInternal(request, response, filterChain);

            // Then
            verify(request).setAttribute("JWT_USER_ID", TEST_USER_ID);
            verify(request).setAttribute("JWT_USERNAME", TEST_USERNAME);
        }
    }

    @Nested
    @DisplayName("Exception Handling Tests")
    class ExceptionHandlingTests {

        @Test
        @DisplayName("Should return 500 error on exception")
        void shouldReturn500OnException() throws Exception {
            // Given
            when(request.getRequestURI()).thenReturn(TEST_URI);
            when(request.getAttribute("RAW-DEVICE-BIND")).thenThrow(new RuntimeException("Test exception"));

            // When
            sessionFilter.doFilterInternal(request, response, filterChain);

            // Then - Filter catches exception and returns 500
            verify(response).sendError(eq(500), anyString());
            verify(filterChain, never()).doFilter(any(), any());
        }
    }
}
