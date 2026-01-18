package one.org.security.core.service.auth;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import one.org.security.api.dto.request.FidoCompleteLoginRequestDTO;
import one.org.security.api.dto.response.AuthResponseDTO;
import one.org.security.common.dto.TokenDTO;
import one.org.security.common.enums.TokenPurposeMessageEnum;
import one.org.security.common.enums.Event;
import one.org.security.core.domain.entity.SecurityEvent;
import one.org.security.core.service.SecurityEventService;
import one.org.security.infrastructure.config.JwtProperties;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import one.org.security.common.service.VerifyUserService;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import one.org.security.api.Errors.CustomExceptions.AccountBlockedException;
import one.org.security.api.Errors.CustomExceptions.UnauthorizedOperationException;
import one.org.security.core.domain.entity.FidoCredential;
import one.org.security.core.domain.entity.User;
import one.org.security.core.service.UserService;
import one.org.security.common.service.RedisService;
import one.org.security.common.service.JwtService;

@Service
@Slf4j
public class FidoService {

    private final UserService userService;
    private final RedisService redisService;
    private final ObjectMapper objectMapper;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final SecurityEventService securityEventService;
    @Autowired
    private VerifyUserService verifyUserService;

    private final String rpId;
    private final String rpName;
    private final Set<String> origins;
    private final int maxLoginAttempts;
    private final int lockoutDurationHours;

    private RelyingParty relyingParty;

    public FidoService(UserService userService,
            RedisService redisService,
            ObjectMapper objectMapper,
            JwtService jwtService,
            JwtProperties jwtProperties,
            SecurityEventService securityEventService,
            VerifyUserService verifyUserService,
            @Value("${fido.rp.id:localhost}") String rpId,
            @Value("${fido.rp.name:Security Service}") String rpName,
            @Value("${fido.rp.origins:http://localhost:10000,http://localhost:3000,http://localhost:8080}") Set<String> origins,
            @Value("${security.policy.max-login-attempts:3}") int maxLoginAttempts,
            @Value("${security.policy.lockout-duration-hours:6}") int lockoutDurationHours) {
        this.userService = userService;
        this.redisService = redisService;
        this.objectMapper = objectMapper;
        this.jwtService = jwtService;
        this.jwtProperties = jwtProperties;
        this.securityEventService = securityEventService;
        this.verifyUserService = verifyUserService;
        this.rpId = rpId;
        this.rpName = rpName;
        this.origins = origins;
        this.maxLoginAttempts = maxLoginAttempts;
        this.lockoutDurationHours = lockoutDurationHours;
    }

    @PostConstruct
    public void init() {
        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
                .id(rpId)
                .name(rpName)
                .build();

        relyingParty = RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(new FidoRepositoryAdapter(userService))
                .origins(origins)
                .build();
    }

    public String initiateRegistration(User user) throws JsonProcessingException {
        if (user.getFidoCredential() != null) {
            throw new UnauthorizedOperationException("User already has a registered FIDO key");
        }

        ByteArray userHandle = new ByteArray(new byte[32]);
        new java.security.SecureRandom().nextBytes(userHandle.getBytes());

        UserIdentity userIdentity = UserIdentity.builder()
                .name(user.getUsername())
                .displayName(user.getUsername())
                .id(userHandle)
                .build();

        PublicKeyCredentialCreationOptions options = relyingParty.startRegistration(
                StartRegistrationOptions.builder()
                        .user(userIdentity)
                        .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                                // .authenticatorAttachment(null) // Allow all (Platform + Cross-Platform)
                                .residentKey(com.yubico.webauthn.data.ResidentKeyRequirement.PREFERRED)
                                .userVerification(com.yubico.webauthn.data.UserVerificationRequirement.REQUIRED)
                                .build())
                        .build());

        // Cache the options to verify later
        redisService.setValue("fido_reg:" + user.getUsername(), options.toJson(), 5, TimeUnit.MINUTES);

        return options.toCredentialsCreateJson();
    }

    public void finishRegistration(String username, String responseJson) {
        try {
            String optionsJson = redisService.getValue("fido_reg:" + username);
            if (optionsJson == null) {
                throw new UnauthorizedOperationException("Registration session expired");
            }

            PublicKeyCredentialCreationOptions options = PublicKeyCredentialCreationOptions.fromJson(optionsJson);
            PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc = PublicKeyCredential
                    .parseRegistrationResponseJson(responseJson);

            RegistrationResult result = relyingParty.finishRegistration(
                    FinishRegistrationOptions.builder()
                            .request(options)
                            .response(pkc)
                            .build());

            User user = userService.getUserByUsername(username);
            // Result doesn't strictly contain userHandle in 2.5.0, it is the one we sent.
            // We use options.getUser().getId() which is the handle.
            ByteArray userHandle = options.getUser().getId();

            FidoCredential credential = FidoCredential.builder()
                    .credentialId(result.getKeyId().getId())
                    .userHandle(userHandle)
                    .publicKey(result.getPublicKeyCose())
                    .signatureCount(result.getSignatureCount())
                    .name("Passkey " + LocalDateTime.now())
                    .build();

            user.setFidoCredential(credential); // Set single field
            user.setPasskeyEnabled(true);
            userService.saveUser(user);

            redisService.deleteValue("fido_reg:" + username);
        } catch (RegistrationFailedException | java.io.IOException e) {
            throw new RuntimeException("Registration failed", e);
        }
    }

    public String initiateLogin(String tempToken, String rawDeviceData) throws JsonProcessingException {
        // Check blocking logic here if needed, or in controller/core service
        TokenDTO data = verifyUserService.verifyUser(tempToken, rawDeviceData, TokenPurposeMessageEnum.LOGIN);
        if (data == null) {
            throw new IllegalArgumentException("wrong token / wrong token used");
        }
        ;
        User user = userService.getUserByUsername(data.subject());
        if (user != null && user.getNumberOfInitaiatedOperations() > maxLoginAttempts) {
            if (user.getLockingTime() != null
                    && user.getLockingTime().plusHours(lockoutDurationHours).isAfter(LocalDateTime.now())) {
                throw new AccountBlockedException("blocked");
            }
        }

        AssertionRequest request = relyingParty.startAssertion(
                com.yubico.webauthn.StartAssertionOptions.builder()
                        .username(data.subject())
                        .build());

        redisService.setValue("fido_login:" + data.subject(), request.toJson(), 5, TimeUnit.MINUTES);

        return request.toCredentialsGetJson();
    }

    public AuthResponseDTO finishLogin(String tempToken, String rawDeviceData,
            FidoCompleteLoginRequestDTO responseJson) {
        try {
            TokenDTO data = verifyUserService.verifyUser(tempToken, rawDeviceData, TokenPurposeMessageEnum.LOGIN);
            if (data == null) {
                throw new IllegalArgumentException("token / device is invaild");
            }
            String requestJson = redisService.getValue("fido_login:" + data.subject());
            if (requestJson == null) {
                throw new UnauthorizedOperationException("Login session expired");
            }
            AssertionRequest request = AssertionRequest.fromJson(requestJson);
            PublicKeyCredential<com.yubico.webauthn.data.AuthenticatorAssertionResponse, com.yubico.webauthn.data.ClientAssertionExtensionOutputs> pkc = PublicKeyCredential
                    .parseAssertionResponseJson(responseJson.getResponse());

            AssertionResult result = relyingParty.finishAssertion(
                    com.yubico.webauthn.FinishAssertionOptions.builder()
                            .request(request)
                            .response(pkc)
                            .build());

            if (result.isSuccess()) {
                User user = userService.getUserByUsername(data.subject());
                // Reset counters
                userService.resetCompletedOperations(user.getId());

                // Update signature count
                updateSignatureCount(user, result.getCredential().getCredentialId(), result.getSignatureCount());
                userService.saveUser(user);

                // Log Success
                String ipAddress = rawDeviceData.split(":")[1];
                logSecurityEvent(user, Event.LOGIN_SUCCESS, "FIDO login successful", ipAddress, data.deviceHash(),
                        data.hmacKeyId());

                redisService.deleteValue("fido_login:" + data.subject());
                return createTokens(user, data.deviceHash(), data.hmacKeyId());
            } else {
                User user = userService.getUserByUsername(data.subject());
                String ipAddress = rawDeviceData.split(":")[1];

                // Atomic increment
                user = userService.incrementCompletedOperations(user.getId());

                if (user.getNumberOfInitaiatedOperations() > maxLoginAttempts) {
                    if (user.getLockingTime() == null) {
                        user.setLockingTime(LocalDateTime.now());
                        userService.saveUser(user);
                    }
                    logSecurityEvent(user, Event.LOGIN_FAIL, "Account blocked due to max FIDO failures", ipAddress,
                            data.deviceHash(), data.hmacKeyId());
                    throw new AccountBlockedException("Account blocked due to multiple failed FIDO attempts");
                }

                logSecurityEvent(user, Event.LOGIN_FAIL, "FIDO authentication failed", ipAddress, data.deviceHash(),
                        data.hmacKeyId());
                throw new BadCredentialsException("FIDO authentication failed");
            }

        } catch (AssertionFailedException | java.io.IOException e) {
            throw new RuntimeException("Login failed", e);
        }
    }

    private void updateSignatureCount(User user, ByteArray credentialId, long count) {
        if (user.getFidoCredential() != null && user.getFidoCredential().getCredentialId().equals(credentialId)) {
            user.getFidoCredential().setSignatureCount(count);
        }
    }

    private AuthResponseDTO createTokens(User user, String deviceHash, String hashKeyId) {
        TokenDTO accessTokenDTO = new TokenDTO(user.getUsername(), user.getId().toHexString(), deviceHash,
                jwtProperties.getAccessExpiration(), hashKeyId, TokenPurposeMessageEnum.ACCESS_TOKEN, null);
        TokenDTO refreshTokenDTO = new TokenDTO(user.getUsername(), user.getId().toHexString(), deviceHash,
                jwtProperties.getRefreshExpiration(), hashKeyId, TokenPurposeMessageEnum.REFRESH_TOKEN, null);
        return new AuthResponseDTO(jwtService.encode(accessTokenDTO), jwtService.encode(refreshTokenDTO));
    }

    // Inner class adapter
    public static class FidoRepositoryAdapter implements com.yubico.webauthn.CredentialRepository {

        private final UserService userService;

        public FidoRepositoryAdapter(UserService userService) {
            this.userService = userService;
        }

        @Override
        public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
            User user = userService.getUserByUsername(username);
            if (user == null || user.getFidoCredential() == null)
                return Collections.emptySet();

            return Collections.singleton(PublicKeyCredentialDescriptor.builder()
                    .id(user.getFidoCredential().getCredentialId())
                    .build());
        }

        @Override
        public Optional<ByteArray> getUserHandleForUsername(String username) {
            User user = userService.getUserByUsername(username);
            if (user == null || user.getFidoCredential() == null)
                return Optional.empty();
            return Optional.of(user.getFidoCredential().getUserHandle());
        }

        @Override
        public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
            // We might need a reverse lookup or just iterate.
            // Ideally we store userHandle in User
            // For now assume user handle is just user ID or stored in fido creds
            // This is an expensive operation without an index on proper field
            // But for this project scope, we might return empty if not strictly needed for
            // username-less flow
            return Optional.empty();
        }

        @Override
        public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
            // We can just use lookupAll to find the credential
            Set<RegisteredCredential> creds = lookupAll(credentialId);
            return creds.stream().findFirst();
        }

        @Override
        public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
            User user = userService.getUserByCredentialId(credentialId);
            if (user != null && user.getFidoCredential() != null) {
                return Collections.singleton(RegisteredCredential.builder()
                        .credentialId(user.getFidoCredential().getCredentialId())
                        .userHandle(user.getFidoCredential().getUserHandle())
                        .publicKeyCose(user.getFidoCredential().getPublicKey())
                        .signatureCount(user.getFidoCredential().getSignatureCount())
                        .build());
            }
            return Collections.emptySet();
        }
    }

    private void logSecurityEvent(User user, Event event, String message, String ipAddress, String deviceHash,
            String deviceHashKeyId) {
        SecurityEvent.SecurityEventBuilder builder = SecurityEvent.builder()
                .user(user.getId())
                .message(message)
                .ipAddress(ipAddress)
                .deviceHash(deviceHash)
                .event(event);

        if (deviceHashKeyId != null) {
            builder.deviceHashKeyId(deviceHashKeyId);
        }

        securityEventService.saveSecurityEvent(builder.build());
    }
}
