package one.org.security.core.service.auth;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import one.org.security.api.dto.request.FidoCompleteLoginRequestDTO;
import one.org.security.api.dto.response.LoginSuccessResponseDTO;
import one.org.security.core.domain.dto.Event;
import one.org.security.core.domain.entity.SecurityEvent;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.exception.AssertionFailedException;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import one.org.security.HmacDTO;
import one.org.security.HmacService;
import one.org.security.api.Errors.CustomExceptions.AccountBlockedException;
import one.org.security.api.Errors.CustomExceptions.UnauthorizedOperationException;
import one.org.security.core.domain.entity.User;
import one.org.security.core.service.Cache.RedisService;
import one.org.security.core.service.SecurityEvent.SecurityEventService;
import one.org.security.core.service.User.UserService;

@Service
@Slf4j
public class FidoService {

    private final UserService userService;
    private final RedisService redisService;
    private final SecurityEventService securityEventService;
    private final HmacService hmacService;

    private final String rpId;
    private final String rpName;
    private final Set<String> origins;
    private final int maxLoginAttempts;
    private final int lockoutDurationHours;

    private RelyingParty relyingParty;

    public FidoService(UserService userService,
            HmacService hmacService,
            RedisService redisService,
            SecurityEventService securityEventService,
            @Value("${fido.rp.id:localhost}") String rpId,
            @Value("${fido.rp.name:Security Service}") String rpName,
            @Value("${fido.rp.origins:http://localhost:10000,http://localhost:3000,http://localhost:8080}") Set<String> origins,
            @Value("${security.policy.max-login-attempts:3}") int maxLoginAttempts,
            @Value("${security.policy.lockout-duration-hours:6}") int lockoutDurationHours) {
        this.userService = userService;
        this.redisService = redisService;
        this.securityEventService = securityEventService;
        this.rpId = rpId;
        this.rpName = rpName;
        this.origins = origins;
        this.maxLoginAttempts = maxLoginAttempts;
        this.lockoutDurationHours = lockoutDurationHours;
        this.hmacService = hmacService;
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

    public String initiateLogin(String username) throws JsonProcessingException {
        User user = userService.getUserByUsername(username);
        if (user == null) {
            throw new IllegalArgumentException("User not found");
        }

        // Check locking
        if (user.getNumberOfInitaiatedOperations() > maxLoginAttempts) {
            if (user.getLockingTime() != null
                    && user.getLockingTime().plusHours(lockoutDurationHours).isAfter(LocalDateTime.now())) {
                throw new AccountBlockedException("blocked");
            }
        }

        AssertionRequest request = relyingParty.startAssertion(
                com.yubico.webauthn.StartAssertionOptions.builder()
                        .username(username)
                        .build());

        redisService.setValue("fido_login:" + username, request.toJson(), 5, TimeUnit.MINUTES);

        return request.toCredentialsGetJson();
    }

    public LoginSuccessResponseDTO finishLogin(String ipAddress, String rawDeviceBind,
            FidoCompleteLoginRequestDTO responseJson, String username) {
        try {
            String requestJson = redisService.getValue("fido_login:" + username);
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
                User user = userService.getUserByUsername(username);
                // Reset counters
                userService.resetCompletedOperations(user.getId());

                userService.saveUser(user);
                HmacDTO hash = hmacService.encode(rawDeviceBind);
                // Log Success
                logSecurityEvent(user, Event.LOGIN_SUCCESS, "FIDO login successful", ipAddress, hash.signature(),
                        hash.keyId());

                redisService.deleteValue("fido_login:" + username);
                HmacDTO session = hmacService.encode(rawDeviceBind+user.getId().toHexString()+username);

                return new LoginSuccessResponseDTO(user.getId().toHexString(),user.getUsername(),session.signature(),session.keyId());
            } else {
                User user = userService.getUserByUsername(username);
                HmacDTO hash = hmacService.encode(rawDeviceBind);
                // Atomic increment
                user = userService.incrementCompletedOperations(user.getId());

                if (user.getNumberOfInitaiatedOperations() > maxLoginAttempts) {
                    if (user.getLockingTime() == null) {
                        user.setLockingTime(LocalDateTime.now());
                        userService.saveUser(user);
                    }
                    logSecurityEvent(user, Event.LOGIN_FAIL, "Account blocked due to max FIDO failures", ipAddress,
                            hash.signature(), hash.keyId());
                    throw new AccountBlockedException("Account blocked due to multiple failed FIDO attempts");
                }

                logSecurityEvent(user, Event.LOGIN_FAIL, "FIDO authentication failed", ipAddress, hash.signature(),
                        hash.keyId());
                throw new BadCredentialsException("FIDO authentication failed");
            }

        } catch (AssertionFailedException | java.io.IOException e) {
            throw new RuntimeException("Login failed", e);
        }
    }

    // private void updateSignatureCount(User user, ByteArray credentialId, long count) {
    //     if (user.getFidoCredential() != null && user.getFidoCredential().getCredentialId().equals(credentialId)) {
    //         user.getFidoCredential().setSignatureCount(count);
    //     }
    // }

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
