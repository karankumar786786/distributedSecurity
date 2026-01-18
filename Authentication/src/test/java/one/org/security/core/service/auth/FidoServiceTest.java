package one.org.security.core.service.auth;


import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.Collections;

import org.bson.types.ObjectId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import static org.mockito.ArgumentMatchers.argThat;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredential;

import one.org.security.api.Errors.CustomExceptions.AccountBlockedException;
import one.org.security.api.dto.request.FidoCompleteLoginRequestDTO;
import one.org.security.core.domain.dto.TokenDTO;
import one.org.security.core.domain.entity.FidoCredential;
import one.org.security.core.domain.entity.User;
import one.org.security.core.domain.enums.Event;
import one.org.security.core.domain.enums.TokenPurposeMessageEnum;
import one.org.security.core.service.SecurityEventService;
import one.org.security.core.service.UserService;
import one.org.security.core.service.VerifyUserService;
import one.org.security.infrastructure.cache.RedisService;
import one.org.security.infrastructure.config.JwtProperties;
import one.org.security.infrastructure.security.JwtService;
import org.springframework.security.authentication.BadCredentialsException;

@ExtendWith(MockitoExtension.class)
public class FidoServiceTest {

    @Mock
    private UserService userService;
    @Mock
    private RedisService redisService;
    @Mock
    private ObjectMapper objectMapper;
    @Mock
    private JwtService jwtService;
    @Mock
    private JwtProperties jwtProperties;
    @Mock
    private SecurityEventService securityEventService;
    @Mock
    private VerifyUserService verifyUserService;
    @Mock
    private RelyingParty relyingParty;

    private FidoService fidoService;

    private User testUser;
    private TokenDTO testTokenDTO;

    @BeforeEach
    void setUp() {
        fidoService = new FidoService(
                userService,
                redisService,
                objectMapper,
                jwtService,
                jwtProperties,
                securityEventService,
                verifyUserService,
                "localhost",
                "Test Service",
                Collections.singleton("http://localhost:3000"),
                3, // max attempts
                6 // lockout hours
        );

        ReflectionTestUtils.setField(fidoService, "relyingParty", relyingParty);

        testUser = User.builder()
                .id(new ObjectId())
                .username("testuser")
                .numberOfInitaiatedOperations(0)
                .fidoCredential(FidoCredential.builder()
                        .credentialId(new ByteArray(new byte[] { 1, 2, 3 }))
                        .build())
                .build();

        testTokenDTO = new TokenDTO(
                "testuser",
                testUser.getId().toHexString(),
                "deviceHash",
                60,
                "keyId",
                TokenPurposeMessageEnum.LOGIN);
    }

    @Test
    void initiateLogin_Success() throws JsonProcessingException {
        when(verifyUserService.verifyUser(anyString(), anyString(), eq(TokenPurposeMessageEnum.LOGIN)))
                .thenReturn(testTokenDTO);
        when(userService.getUserByUsername("testuser")).thenReturn(testUser);

        AssertionRequest mockRequest = mock(AssertionRequest.class);
        when(mockRequest.toJson()).thenReturn("{}");
        when(mockRequest.toCredentialsGetJson()).thenReturn("{}");

        when(relyingParty.startAssertion(any(StartAssertionOptions.class))).thenReturn(mockRequest);

        String result = fidoService.initiateLogin("validToken", "ip:127.0.0.1");

        assertNotNull(result);
        verify(redisService).setValue(eq("fido_login:testuser"), anyString(), eq(5L), any());
    }

    @Test
    void initiateLogin_Blocked() {
        when(verifyUserService.verifyUser(anyString(), anyString(), eq(TokenPurposeMessageEnum.LOGIN)))
                .thenReturn(testTokenDTO);

        testUser.setNumberOfInitaiatedOperations(4);
        testUser.setLockingTime(LocalDateTime.now().plusHours(1)); // Already blocked
        when(userService.getUserByUsername("testuser")).thenReturn(testUser);

        assertThrows(AccountBlockedException.class, () -> fidoService.initiateLogin("validToken", "ip:127.0.0.1"));

        verify(relyingParty, never()).startAssertion(any());
    }

    @Test
    void finishLogin_Success() throws Exception {
        when(verifyUserService.verifyUser(anyString(), anyString(), eq(TokenPurposeMessageEnum.LOGIN)))
                .thenReturn(testTokenDTO);
        when(redisService.getValue("fido_login:testuser")).thenReturn("{}");
        when(userService.getUserByUsername("testuser")).thenReturn(testUser);
        when(jwtService.encode(any(TokenDTO.class))).thenReturn("token");

        AssertionResult mockResult = mock(AssertionResult.class);
        when(mockResult.isSuccess()).thenReturn(true);
        when(mockResult.getCredential()).thenReturn(RegisteredCredential.builder()
                .credentialId(new ByteArray(new byte[] { 1, 2, 3 }))
                .userHandle(new ByteArray(new byte[] { 1 }))
                .publicKeyCose(new ByteArray(new byte[] { 1 }))
                .signatureCount(10)
                .build());

        try (MockedStatic<AssertionRequest> arMock = Mockito.mockStatic(AssertionRequest.class);
                MockedStatic<PublicKeyCredential> pkcMock = Mockito.mockStatic(PublicKeyCredential.class)) {

            arMock.when(() -> AssertionRequest.fromJson(anyString())).thenReturn(mock(AssertionRequest.class));
            pkcMock.when(() -> PublicKeyCredential.parseAssertionResponseJson(any()))
                    .thenReturn(mock(PublicKeyCredential.class));

            when(relyingParty.finishAssertion(any(FinishAssertionOptions.class))).thenReturn(mockResult);

            FidoCompleteLoginRequestDTO requestDTO = new FidoCompleteLoginRequestDTO();
            requestDTO.setResponse("{}");

            fidoService.finishLogin("validToken", "ip:127.0.0.1", requestDTO);

            verify(userService).resetCompletedOperations(testUser.getId());
            verify(userService).saveUser(testUser);
            verify(securityEventService).saveSecurityEvent(argThat(event -> event.getEvent() == Event.LOGIN_SUCCESS));
        }
    }

    @Test
    void finishLogin_Failure_Increment() throws Exception {
        when(verifyUserService.verifyUser(anyString(), anyString(), eq(TokenPurposeMessageEnum.LOGIN)))
                .thenReturn(testTokenDTO);
        when(redisService.getValue("fido_login:testuser")).thenReturn("{}");
        when(userService.getUserByUsername("testuser")).thenReturn(testUser);

        // Return updated user to simulate increment result
        User updated = User.builder().id(testUser.getId()).username("testuser").numberOfInitaiatedOperations(1).build();
        when(userService.incrementCompletedOperations(testUser.getId())).thenReturn(updated);

        AssertionResult mockResult = mock(AssertionResult.class);
        when(mockResult.isSuccess()).thenReturn(false);

        try (MockedStatic<AssertionRequest> arMock = Mockito.mockStatic(AssertionRequest.class);
                MockedStatic<PublicKeyCredential> pkcMock = Mockito.mockStatic(PublicKeyCredential.class)) {

            arMock.when(() -> AssertionRequest.fromJson(anyString())).thenReturn(mock(AssertionRequest.class));
            pkcMock.when(() -> PublicKeyCredential.parseAssertionResponseJson(any()))
                    .thenReturn(mock(PublicKeyCredential.class));

            when(relyingParty.finishAssertion(any(FinishAssertionOptions.class))).thenReturn(mockResult);

            FidoCompleteLoginRequestDTO requestDTO = new FidoCompleteLoginRequestDTO();
            requestDTO.setResponse("{}");

            assertThrows(BadCredentialsException.class,
                    () -> fidoService.finishLogin("validToken", "ip:127.0.0.1", requestDTO));

            verify(userService).incrementCompletedOperations(testUser.getId());
            verify(securityEventService).saveSecurityEvent(
                    argThat(event -> event.getEvent() == Event.LOGIN_FAIL && event.getMessage().contains("failed")));
        }
    }

    @Test
    void finishLogin_Failure_BlockingLimit() throws Exception {
        when(verifyUserService.verifyUser(anyString(), anyString(), eq(TokenPurposeMessageEnum.LOGIN)))
                .thenReturn(testTokenDTO);
        when(redisService.getValue("fido_login:testuser")).thenReturn("{}");
        when(userService.getUserByUsername("testuser")).thenReturn(testUser);

        User blocked = User.builder().id(testUser.getId()).username("testuser").numberOfInitaiatedOperations(4).build();
        when(userService.incrementCompletedOperations(testUser.getId())).thenReturn(blocked);

        AssertionResult mockResult = mock(AssertionResult.class);
        when(mockResult.isSuccess()).thenReturn(false);

        try (MockedStatic<AssertionRequest> arMock = Mockito.mockStatic(AssertionRequest.class);
                MockedStatic<PublicKeyCredential> pkcMock = Mockito.mockStatic(PublicKeyCredential.class)) {

            arMock.when(() -> AssertionRequest.fromJson(anyString())).thenReturn(mock(AssertionRequest.class));
            pkcMock.when(() -> PublicKeyCredential.parseAssertionResponseJson(any()))
                    .thenReturn(mock(PublicKeyCredential.class));

            when(relyingParty.finishAssertion(any(FinishAssertionOptions.class))).thenReturn(mockResult);

            FidoCompleteLoginRequestDTO requestDTO = new FidoCompleteLoginRequestDTO();
            requestDTO.setResponse("{}");

            assertThrows(AccountBlockedException.class,
                    () -> fidoService.finishLogin("validToken", "ip:127.0.0.1", requestDTO));

            verify(userService).saveUser(argThat(user -> user.getLockingTime() != null));
            verify(securityEventService).saveSecurityEvent(
                    argThat(event -> event.getEvent() == Event.LOGIN_FAIL && event.getMessage().contains("blocked")));
        }
    }
}
