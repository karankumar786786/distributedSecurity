package one.org.security.Resource.api.controller;

import one.org.security.Resource.core.domain.entity.ResourceEntity;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class ResourceControllerTest {

        @Mock
        private VerifyUserService verifyUserService;

        @InjectMocks
        private ResourceController resourceController;

        @Test
        public void testGetResource_NoToken_Unauthorized() {
                when(verifyUserService.verifyUser(anyString(), anyString(), any(TokenPurposeMessageEnum.class)))
                                .thenReturn(null);

                ResponseEntity<ResourceEntity> response = resourceController.getResource(
                                "invalid_token", "device_hash_data");

                assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        }

        @Test
        public void testGetResource_WithValidToken() {
                TokenDTO mockToken = new TokenDTO(
                                "user123", // subject
                                "test_key_id", // id
                                "device_hash_data", // deviceHash
                                60, // expiration
                                "test_hmac_key", // hmacKeyId
                                TokenPurposeMessageEnum.ACCESS_TOKEN, // purpose
                                List.of("read")); // scope

                when(verifyUserService.verifyUser(anyString(), anyString(), any(TokenPurposeMessageEnum.class)))
                                .thenReturn(mockToken);

                ResponseEntity<ResourceEntity> response = resourceController.getResource(
                                "Bearer valid_token", "device_hash_data");

                assertEquals(HttpStatus.OK, response.getStatusCode());
                assertNotNull(response.getBody());
                assertEquals("Demo Resource", response.getBody().getName());
        }

        @Test
        public void testGetResource_WithInvalidScope() {
                TokenDTO mockToken = new TokenDTO(
                                "user123", // subject
                                "test_key_id", // id
                                "device_hash_data", // deviceHash
                                60, // expiration
                                "test_hmac_key", // hmacKeyId
                                TokenPurposeMessageEnum.ACCESS_TOKEN, // purpose
                                List.of("none")); // scope

                when(verifyUserService.verifyUser(anyString(), anyString(), any(TokenPurposeMessageEnum.class)))
                                .thenReturn(mockToken);

                ResponseEntity<ResourceEntity> response = resourceController.getResource(
                                "Bearer valid_token", "device_hash_data");

                assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        }
}
