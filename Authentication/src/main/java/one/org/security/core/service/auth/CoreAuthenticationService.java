package one.org.security.core.service.auth;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;
import one.org.security.api.Errors.CustomExceptions.AccountBlockedException;
import one.org.security.api.Errors.CustomExceptions.InvalidTokenException;
import one.org.security.api.Errors.CustomExceptions.UnauthorizedOperationException;
import one.org.security.api.dto.request.CheckUserExistRequestDTO;
import one.org.security.api.dto.request.LoginRequestDTO;
import one.org.security.api.dto.request.RegisterRequestDTO;
import one.org.security.api.dto.response.AuthResponseDTO;
import one.org.security.api.dto.response.CheckUserExistResponseDTO;
import one.org.security.core.domain.dto.HmacDTO;
import one.org.security.core.domain.dto.TokenDTO;
import one.org.security.core.domain.entity.SecurityEvent;
import one.org.security.core.domain.entity.User;
import one.org.security.core.domain.enums.CheckUserExistRequestAvailableEnum;
import one.org.security.core.domain.enums.Event;
import one.org.security.core.domain.enums.LoginOptionsEnum;
import one.org.security.core.domain.enums.TokenPurposeMessageEnum;
import one.org.security.core.service.SecurityEventService;
import one.org.security.core.service.UserService;
import one.org.security.core.service.VerifyUserService;

import one.org.security.infrastructure.security.HmacService;
import one.org.security.infrastructure.security.JwtService;
import one.org.security.infrastructure.security.filter.EncodingService;
import one.org.security.infrastructure.config.JwtProperties;

@Service
@Slf4j
public class CoreAuthenticationService {

    @Autowired
    private EncodingService encodingService;
    @Autowired
    private UserService userService;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private SecurityEventService securityEventService;
    @Autowired
    private HmacService hmacService;
    @Autowired
    private VerifyUserService verifyUserService;
    @Autowired
    private JwtProperties jwtProperties;

    public AuthResponseDTO register(RegisterRequestDTO registerRequest, String rawDeviceData) {
        String ipAddress = rawDeviceData.split(":")[1];
        HmacDTO hash = hmacService.encode(rawDeviceData);

        User newUser = User.builder()
                .backupEmail("")
                .password(encodingService.encode(registerRequest.password()))
                .username(registerRequest.username())
                .isAccountLocked(false)
                .passkeyEnabled(false)
                .phoneNumberVerified(false)
                .phoneNumber("")
                .lockingTime(LocalDateTime.now())
                .numberOfInitaiatedOperations(0)
                .knownDeviceHashes(new ArrayList<>(Collections.singletonList(hash.signature())))
                .build();
        userService.saveUser(newUser);

        logSecurityEvent(newUser, Event.REGISTER, null, ipAddress, hash.signature(), hash.keyId());
        return createTokens(newUser, hash.signature(), hash.keyId());
    }

    public CheckUserExistResponseDTO checkUserExist(CheckUserExistRequestDTO request, String rawDeviceData) {
        User user = userService.getUserByUsername(request.username());
        if (user == null) {
            return new CheckUserExistResponseDTO(false, null, null);
        }

        if (user.getNumberOfInitaiatedOperations() > 3) {
            if (user.getLockingTime() != null && user.getLockingTime().plusHours(6).isAfter(LocalDateTime.now())) {
                throw new AccountBlockedException(
                        "this account is blocked for some time due to max no of operartioninitiated complete the operation or wait for 6hr from "
                                + user.getLockingTime());
            } else {
                user.setNumberOfInitaiatedOperations(0);
                user.setLockingTime(null);
                userService.saveUser(user);
            }
        }

        user.setNumberOfInitaiatedOperations(user.getNumberOfInitaiatedOperations() + 1);
        if (user.getNumberOfInitaiatedOperations() > 3) {
            user.setLockingTime(LocalDateTime.now());
            userService.saveUser(user);
            throw new AccountBlockedException(
                    "this account is blocked for some time due to max no of operartioninitiated complete the operation or wait for 6hr from "
                            + user.getLockingTime());
        }
        userService.saveUser(user);

        Map<String, Boolean> data = new HashMap<>();
        if (request.reason() == CheckUserExistRequestAvailableEnum.LOGIN) {
            data.put("passKeyLoginAvailable", user.isPasskeyEnabled());
            data.put("passwordLoginAvailable", true);
        } else if (request.reason() != CheckUserExistRequestAvailableEnum.OTHER) {
            if (!user.isBackupEmailVerified() && !user.isPhoneNumberVerified()) {
                data.put("accountLost", true);
                return new CheckUserExistResponseDTO(true, data, null);
            }
            data.put("backUpEmail", user.isBackupEmailVerified());
            data.put("phoneNumberVerified", user.isPhoneNumberVerified());
        } else {
            data = null;
        }
        ;

        HmacDTO hash = hmacService.encode(rawDeviceData);
        TokenDTO tempTokenDTO = new TokenDTO(user.getUsername(), user.getId().toHexString(), hash.signature(),
                jwtProperties.getTempExpiration(), hash.keyId(), TokenPurposeMessageEnum.TEMP_TOKEN);
        if (request.reason() == CheckUserExistRequestAvailableEnum.LOGIN) {
            tempTokenDTO = new TokenDTO(user.getUsername(), user.getId().toHexString(), hash.signature(),
                    jwtProperties.getTempExpiration(), hash.keyId(), TokenPurposeMessageEnum.LOGIN);
        } else if (request.reason() == CheckUserExistRequestAvailableEnum.FORGET_PASSWORD) {
            tempTokenDTO = new TokenDTO(user.getUsername(), user.getId().toHexString(), hash.signature(),
                    jwtProperties.getTempExpiration(), hash.keyId(), TokenPurposeMessageEnum.FORGET_PASSWORD);
        }
        String tempToken = jwtService.encode(tempTokenDTO);

        return new CheckUserExistResponseDTO(true, data, tempToken);
    }

    public AuthResponseDTO login(LoginRequestDTO loginRequest, String tempToken, String rawDeviceData) {
        String ipAddress = rawDeviceData.split(":")[1];
        TokenDTO data = verifyTempToken(tempToken, rawDeviceData, TokenPurposeMessageEnum.LOGIN);
        User user = userService.getUserById(new ObjectId(data.id()));
        if (!encodingService.verify(loginRequest.credential(), user.getPassword())) {
            logSecurityEvent(user, Event.LOGIN_FAIL, "due to wrong password", ipAddress, data.deviceHash(),
                    data.hmacKeyId());
            throw new BadCredentialsException("Invalid password");
        }
        user.setNumberOfInitaiatedOperations(0);
        user.setLockingTime(null);
        userService.saveUser(user);

        logSecurityEvent(user, Event.LOGIN_SUCCESS, null, ipAddress, data.deviceHash(), data.hmacKeyId());
        return createTokens(user, data.deviceHash(), data.hmacKeyId());
    }

    // --- Helpers ---

    private AuthResponseDTO createTokens(User user, String deviceHash, String hashKeyId) {
        TokenDTO accessTokenDTO = new TokenDTO(user.getUsername(), user.getId().toHexString(), deviceHash,
                jwtProperties.getAccessExpiration(), hashKeyId, TokenPurposeMessageEnum.ACCESS_TOKEN);
        TokenDTO refreshTokenDTO = new TokenDTO(user.getUsername(), user.getId().toHexString(), deviceHash,
                jwtProperties.getRefreshExpiration(), hashKeyId, TokenPurposeMessageEnum.REFRESH_TOKEN);
        return new AuthResponseDTO(jwtService.encode(accessTokenDTO), jwtService.encode(refreshTokenDTO));
    }

    private TokenDTO verifyTempToken(String token, String rawDeviceData, TokenPurposeMessageEnum purpose) {
        TokenDTO data = verifyUserService.verifyUser(token, rawDeviceData, purpose);
        if (data == null) {
            throw new InvalidTokenException("Invalid or expired token");
        }
        return data;
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
