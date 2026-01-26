package one.org.security.core.service.auth;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
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
import com.yubico.webauthn.exception.RegistrationFailedException;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import one.org.security.api.Errors.CustomExceptions.UnauthorizedOperationException;
import one.org.security.core.domain.entity.FidoCredential;
import one.org.security.core.domain.entity.User;
import one.org.security.core.service.Cache.RedisService;
import one.org.security.core.service.User.UserService;

@Service
@Slf4j
public class FidoRegistrationService {

    private final UserService userService;
    private final RedisService redisService;

    private final String rpId;
    private final String rpName;
    private final Set<String> origins;

    private RelyingParty relyingParty;

    public FidoRegistrationService(UserService userService,
            RedisService redisService,
            @Value("${fido.rp.id:localhost}") String rpId,
            @Value("${fido.rp.name:Security Service}") String rpName,
            @Value("${fido.rp.origins:http://localhost:10000,http://localhost:3000,http://localhost:8080}") Set<String> origins) {
        this.userService = userService;
        this.redisService = redisService;
        this.rpId = rpId;
        this.rpName = rpName;
        this.origins = origins;
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
                                .residentKey(com.yubico.webauthn.data.ResidentKeyRequirement.PREFERRED)
                                .userVerification(com.yubico.webauthn.data.UserVerificationRequirement.REQUIRED)
                                .build())
                        .build());

        redisService.setValue("fido_reg:" + user.getId().toHexString(), options.toJson(), 5, TimeUnit.MINUTES);

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

            User user = userService.getUserById(new ObjectId(username));
            ByteArray userHandle = options.getUser().getId();

            FidoCredential credential = FidoCredential.builder()
                    .credentialId(result.getKeyId().getId())
                    .userHandle(userHandle)
                    .publicKey(result.getPublicKeyCose())
                    .signatureCount(result.getSignatureCount())
                    .name("Passkey " + LocalDateTime.now())
                    .build();

            user.setFidoCredential(credential);
            user.setPasskeyEnabled(true);
            userService.saveUser(user);

            redisService.deleteValue("fido_reg:" + username);
        } catch (RegistrationFailedException | java.io.IOException e) {
            throw new RuntimeException("Registration failed", e);
        }
    }

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
            return Optional.empty();
        }

        @Override
        public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
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
}
