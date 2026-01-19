package one.org.security.Authorization.api.controller;

import one.org.security.Authorization.core.domain.entity.clientEntity;
import one.org.security.Authorization.core.service.ClientService;
import one.org.security.Authorization.core.service.OAuth2Service;
import one.org.security.common.dto.TokenDTO;
import one.org.security.common.enums.TokenPurposeMessageEnum;
import one.org.security.common.service.VerifyUserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class AuthorizationControllerTest {

        @Mock
        private ClientService clientService;

        @Mock
        private OAuth2Service oAuth2Service;

        @Mock
        private VerifyUserService verifyUserService;

        @InjectMocks
        private AuthorizationController authorizationController;

        private static final String DEVICE_DATA = "device_hash_data";

        @Test
        public void testAuthorize_ValidUser_ReturnsCode() {
                TokenDTO mockUserAuth = new TokenDTO(
                                "user123", "user_auth_id", "device_hash", 60, "hmac_key",
                                TokenPurposeMessageEnum.ACCESS_TOKEN, null);

                when(verifyUserService.verifyUser(anyString(), anyString(), any(TokenPurposeMessageEnum.class)))
                                .thenReturn(mockUserAuth);

                when(oAuth2Service.authorize(anyString(), anyString(), anyList()))
                                .thenReturn("auth_code_123");

                ResponseEntity<Map<String, String>> response = authorizationController.authorize(
                                "Bearer valid_token", DEVICE_DATA, "client_1", "read");

                assertEquals(HttpStatus.OK, response.getStatusCode());
                assertNotNull(response.getBody());
                assertEquals("auth_code_123", response.getBody().get("code"));
        }

        @Test
        public void testAuthorize_InvalidUser_Unauthorized() {
                when(verifyUserService.verifyUser(anyString(), anyString(), any(TokenPurposeMessageEnum.class)))
                                .thenReturn(null);

                ResponseEntity<Map<String, String>> response = authorizationController.authorize(
                                "Bearer invalid_token", DEVICE_DATA, "client_1", "read");

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

                ResponseEntity<Map<String, String>> response = authorizationController.token(
                                "authorization_code", "valid_code", "client_1", "secret");

                assertEquals(HttpStatus.OK, response.getStatusCode());
                assertNotNull(response.getBody());
                assertEquals("access_token_jwt", response.getBody().get("access_token"));
        }

        @Test
        public void testToken_InvalidGrantType_BadRequest() {
                ResponseEntity<Map<String, String>> response = authorizationController.token(
                                "password", "valid_code", "client_1", "secret");

                assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
                assertEquals("unsupported_grant_type", response.getBody().get("error"));
        }

        @Test
        public void testToken_InvalidClient_Unauthorized() {
                when(clientService.getClient("invalid_client")).thenReturn(null);

                ResponseEntity<Map<String, String>> response = authorizationController.token(
                                "authorization_code", "valid_code", "invalid_client", "secret");

                assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
                assertEquals("invalid_client", response.getBody().get("error"));
        }

        @Test
        public void testRegisterClient_ValidUser_ReturnsClient() {
                TokenDTO mockUserAuth = new TokenDTO(
                                "user123", "user_auth_id", "device_hash", 60, "hmac_key",
                                TokenPurposeMessageEnum.ACCESS_TOKEN, null);

                clientEntity mockClient = clientEntity.builder()
                                .clientId("new_client_id")
                                .userId(new org.bson.types.ObjectId())
                                .redirectUrls(List.of("http://lb"))
                                .build();

                when(verifyUserService.verifyUser(anyString(), anyString(), any(TokenPurposeMessageEnum.class)))
                                .thenReturn(mockUserAuth);
                when(clientService.registerClient(anyString(), anyString())).thenReturn(mockClient);

                ResponseEntity<clientEntity> response = authorizationController.registerClient(
                                "Bearer valid_token", DEVICE_DATA, Map.of("redirectUrl", "http://lb"));

                assertEquals(HttpStatus.OK, response.getStatusCode());
                assertNotNull(response.getBody());
                assertEquals("new_client_id", response.getBody().getClientId());
        }
}
