package one.org.security.Authorization.api.controller;

import one.org.security.Authorization.core.domain.entity.clientEntity;
import one.org.security.Authorization.core.service.ClientService;
import one.org.security.Authorization.core.service.OAuth2Service;
import one.org.security.common.dto.TokenDTO;
import one.org.security.common.model.AuthenticatedUser;
import one.org.security.common.enums.TokenPurposeMessageEnum;
import one.org.security.common.service.VerifyUserService;
import one.org.security.Authorization.api.exception.GlobalExceptionHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
public class AuthorizationControllerTest {

        @Mock
        private ClientService clientService;

        @Mock
        private OAuth2Service oAuth2Service;

        @InjectMocks
        private AuthorizationController authorizationController;

        private MockMvc mockMvc;
        private ObjectMapper objectMapper = new ObjectMapper();

        @BeforeEach
        void setUp() {
                mockMvc = MockMvcBuilders.standaloneSetup(authorizationController)
                                .setControllerAdvice(new GlobalExceptionHandler())
                                .build();
        }

        @Test
        public void testAuthorize_ValidUser_ReturnsCode() {
                TokenDTO tokenDTO = new TokenDTO("testUser", "123", "hash", 10, "key",
                                TokenPurposeMessageEnum.ACCESS_TOKEN, List.of("read"));
                AuthenticatedUser user = new AuthenticatedUser(tokenDTO);

                when(oAuth2Service.authorize(anyString(), anyString(), anyList())).thenReturn("auth_code");

                one.org.security.Authorization.api.dto.AuthorizeRequestDTO request = one.org.security.Authorization.api.dto.AuthorizeRequestDTO
                                .builder()
                                .clientId("client1")
                                .scope("read")
                                .build();

                ResponseEntity<one.org.security.Authorization.api.dto.AuthorizeResponseDTO> response = authorizationController
                                .authorize(user, request);

                assertEquals(HttpStatus.OK, response.getStatusCode());
                assertNotNull(response.getBody());
                assertEquals("auth_code", response.getBody().getCode());
        }

        @Test
        public void testAuthorize_InvalidUser_Unauthorized() {
                one.org.security.Authorization.api.dto.AuthorizeRequestDTO request = one.org.security.Authorization.api.dto.AuthorizeRequestDTO
                                .builder()
                                .clientId("client_1")
                                .scope("read")
                                .build();

                ResponseEntity<one.org.security.Authorization.api.dto.AuthorizeResponseDTO> response = authorizationController
                                .authorize(
                                                null, request);

                assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        }

        @Test
        public void testToken_ValidCode_ReturnsToken() {
                clientEntity mockClient = clientEntity.builder()
                                .clientId("client_1")
                                .userId(new org.bson.types.ObjectId())
                                .build();
                TokenDTO mockToken = new TokenDTO(
                                "user123", "token_id", "device_hash", 60, "hmac_key",
                                TokenPurposeMessageEnum.ACCESS_TOKEN,
                                List.of("read"));

                when(clientService.getClient("client_1")).thenReturn(mockClient);
                when(oAuth2Service.exchangeToken(anyString(), anyString(), anyString(), any(clientEntity.class)))
                                .thenReturn(mockToken);
                when(oAuth2Service.generateJwt(mockToken)).thenReturn("access_token_jwt");

                one.org.security.Authorization.api.dto.TokenRequestDTO request = one.org.security.Authorization.api.dto.TokenRequestDTO
                                .builder()
                                .grantType("authorization_code")
                                .code("valid_code")
                                .clientId("client_1")
                                .clientSecret("secret")
                                .build();

                ResponseEntity<one.org.security.Authorization.api.dto.TokenResponseDTO> response = authorizationController
                                .token(request);

                assertEquals(HttpStatus.OK, response.getStatusCode());
                assertNotNull(response.getBody());
                assertEquals("access_token_jwt", response.getBody().getAccessToken());
        }

        @Test
        public void testToken_InvalidGrantType_BadRequest() {
                one.org.security.Authorization.api.dto.TokenRequestDTO request = one.org.security.Authorization.api.dto.TokenRequestDTO
                                .builder()
                                .grantType("password")
                                .code("valid_code")
                                .clientId("client_1")
                                .clientSecret("secret")
                                .build();

                ResponseEntity<one.org.security.Authorization.api.dto.TokenResponseDTO> response = authorizationController
                                .token(request);

                assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
                assertEquals("unsupported_grant_type", response.getBody().getError());
        }

        @Test
        public void testToken_InvalidClient_Unauthorized() {
                when(clientService.getClient("invalid_client")).thenReturn(null);

                one.org.security.Authorization.api.dto.TokenRequestDTO request = one.org.security.Authorization.api.dto.TokenRequestDTO
                                .builder()
                                .grantType("authorization_code")
                                .code("valid_code")
                                .clientId("invalid_client")
                                .clientSecret("secret")
                                .build();

                ResponseEntity<one.org.security.Authorization.api.dto.TokenResponseDTO> response = authorizationController
                                .token(request);

                assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
                assertEquals("invalid_client", response.getBody().getError());
        }

        @Test
        public void testRegisterClient_ValidUser_ReturnsClient() throws Exception {
                TokenDTO tokenDTO = new TokenDTO("testUser", "123", "hash", 10, "key",
                                TokenPurposeMessageEnum.ACCESS_TOKEN, List.of("read"));
                AuthenticatedUser user = new AuthenticatedUser(tokenDTO);

                one.org.security.Authorization.api.dto.ClientRegistrationRequestDTO request = one.org.security.Authorization.api.dto.ClientRegistrationRequestDTO
                                .builder()
                                .redirectUrl("http://example.com")
                                .clientName("Test Client")
                                .scopes(List.of("read"))
                                .build();

                when(clientService.registerClient(anyString(),
                                any(one.org.security.Authorization.api.dto.ClientRegistrationRequestDTO.class)))
                                .thenReturn(one.org.security.Authorization.api.dto.ClientRegistrationResponseDTO
                                                .builder()
                                                .clientId("new_client_id")
                                                .clientSecret("secret")
                                                .build());

                ResponseEntity<one.org.security.Authorization.api.dto.ClientRegistrationResponseDTO> response = authorizationController
                                .registerClient(user, request);

                assertEquals(HttpStatus.OK, response.getStatusCode());
                assertNotNull(response.getBody());
                assertEquals("new_client_id", response.getBody().getClientId());
        }

        @Test
        public void testRegisterClient_InvalidRequest_BadRequest() throws Exception {
                one.org.security.Authorization.api.dto.ClientRegistrationRequestDTO request = one.org.security.Authorization.api.dto.ClientRegistrationRequestDTO
                                .builder()
                                .build(); // Missing required fields

                mockMvc.perform(post("/client/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isBadRequest());
        }

        @Test
        public void testAuthorize_InvalidRequest_BadRequest() throws Exception {
                one.org.security.Authorization.api.dto.AuthorizeRequestDTO request = one.org.security.Authorization.api.dto.AuthorizeRequestDTO
                                .builder()
                                .build(); // Missing required fields

                // Note: We don't need to mock Authentication principal here because
                // standaloneSetup doesn't enforce security unless explicitly configured
                // BUT our Controller method expects @AuthenticationPrincipal.
                // In standaloneSetup, the argument resolver for AuthenticationPrincipal might
                // return null or need configuration.
                // For simple validation testing, we just want to hit the validator.
                // However, if the controller checks for user != null BEFORE validation, we
                // might hit 401 instead of 400.
                // The endpoint logic is:
                // if (user == null) return 401;
                // The @Valid annotation is on the request body. Validation usually happens
                // BEFORE the method body execution.
                // So we should expect 400 if validation fails, even if user is null.
                // Wait, argument resolution happens, then validation.

                mockMvc.perform(post("/oauth2/authorize")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isBadRequest());
        }

        @Test
        public void testToken_InvalidRequest_BadRequest() throws Exception {
                one.org.security.Authorization.api.dto.TokenRequestDTO request = one.org.security.Authorization.api.dto.TokenRequestDTO
                                .builder()
                                .build(); // Missing required fields

                mockMvc.perform(post("/oauth2/token")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isBadRequest());
        }
}
