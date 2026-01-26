package one.org.security.core.service.auth;


import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;
import one.org.security.HmacDTO;
import one.org.security.HmacService;
import one.org.security.api.Errors.CustomExceptions.AccountBlockedException;
import one.org.security.api.Errors.CustomExceptions.UserNotFoundException;
import one.org.security.api.dto.enums.CheckUserExistRequestAvailableEnum;
import one.org.security.api.dto.request.CheckUserExistRequestDTO;
import one.org.security.api.dto.request.LoginRequestDTO;
import one.org.security.api.dto.request.RegisterRequestDTO;
import one.org.security.api.dto.response.CheckUserExistResponseDTO;
import one.org.security.api.dto.response.LoginSuccessResponseDTO;
import one.org.security.core.domain.dto.Event;
import one.org.security.core.domain.entity.SecurityEvent;
import one.org.security.core.domain.entity.User;
import one.org.security.core.service.PasswordEncoding.EncodingService;
import one.org.security.core.service.SecurityEvent.SecurityEventService;
import one.org.security.core.service.User.UserService;

@Service
@Slf4j
public class CoreAuthenticationService {

    @Autowired
    private EncodingService encodingService;
    @Autowired
    private UserService userService;
    @Autowired
    private SecurityEventService securityEventService;
    @Autowired
    private HmacService hmacService;

    @Value("${security.policy.max-login-attempts:3}")
    private int maxLoginAttempts;

    @Value("${security.policy.lockout-duration-hours:6}")
    private int lockoutDurationHours;

    public void register(RegisterRequestDTO registerRequest,String rawDeviceBind, String ipAddress) {
        HmacDTO hash = hmacService.encode(rawDeviceBind);
        User newUser = User.builder()
                .backupEmail("")
                .password(encodingService.encode(registerRequest.getPassword()))
                .username(registerRequest.getUsername())
                .isAccountLocked(false)
                .passkeyEnabled(false)
                .phoneNumberVerified(false)
                .phoneNumber("")
                .lockingTime(LocalDateTime.now())
                .numberOfInitaiatedOperations(0)
                .knownDeviceHashes(new ArrayList<>(Collections.singletonList(hash.signature())))
                .build();
        userService.saveUser(newUser);
        // device signature and device keyid
        logSecurityEvent(newUser, Event.REGISTER, null, ipAddress, hash.signature(), hash.keyId());
        // Auto-login after register? Or just return success.
        // For now, let's return success message.
        return;
    }

    public CheckUserExistResponseDTO checkUserExist(CheckUserExistRequestDTO request, String rawDeviceBind, String ipAddress) {
        User user = userService.getUserByUsername(request.username());
        if (user == null) {
            return new CheckUserExistResponseDTO(false, null,null,"","");
        };
        HmacDTO initSession = hmacService.encode(rawDeviceBind+request.reason()+user.getId().toHexString()+user.getUsername());

        if (user.getNumberOfInitaiatedOperations() > maxLoginAttempts) {
            if (user.getLockingTime() != null
                    && user.getLockingTime().plusHours(lockoutDurationHours).isAfter(LocalDateTime.now())) {
                throw new AccountBlockedException(
                        "this account is blocked for some time due to max no of operartioninitiated complete the operation or wait for "
                                + lockoutDurationHours + "hr from "
                                + user.getLockingTime());
            } else {
                user.setNumberOfInitaiatedOperations(0);
                user.setLockingTime(null);
                userService.saveUser(user);
            }
        }

        user.setNumberOfInitaiatedOperations(user.getNumberOfInitaiatedOperations() + 1);
        if (user.getNumberOfInitaiatedOperations() > maxLoginAttempts) {
            user.setLockingTime(LocalDateTime.now());
            userService.saveUser(user);
            throw new AccountBlockedException(
                    "this account is blocked for some time due to max no of operartioninitiated complete the operation or wait for "
                            + lockoutDurationHours + "hr from "
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
                return new CheckUserExistResponseDTO(true, data,initSession,"","");
            }
            data.put("backUpEmail", user.isBackupEmailVerified());
            data.put("phoneNumberVerified", user.isPhoneNumberVerified());
        } else {
            data = null;
        }
        ;
        return new CheckUserExistResponseDTO(true, data,initSession,"","");
    }

    public String initPasswordLogin(String username) {
        return String.valueOf(UUID.randomUUID());
    }

    public LoginSuccessResponseDTO completePasswordLogin(LoginRequestDTO loginRequest, String username,
            String ipAddress, String rawDeviceBind) {
        User user = userService.getUserByUsername(username);
        if (user == null) {
            throw new UserNotFoundException("user not found");
        }
        ;
        boolean verifyPassword = encodingService.verify(loginRequest.credential(), user.getPassword());
        HmacDTO hash = hmacService.encode(rawDeviceBind);
        if (!verifyPassword) {
            user.setNumberOfInitaiatedOperations(user.getNumberOfInitaiatedOperations() + 1);
            if (user.getNumberOfInitaiatedOperations() > maxLoginAttempts) {
                user.setLockingTime(LocalDateTime.now());
                user.setAccountLocked(true);
                logSecurityEvent(user, Event.ACCOUNT_LOCKED, "password missmatched", ipAddress, hash.signature(),
                        hash.keyId());
                throw new AccountBlockedException(
                        "this account is blocked for some time due to max no of operartioninitiated complete the operation or wait for "
                                + lockoutDurationHours + "hr from "
                                + user.getLockingTime());
            }
            ;
            logSecurityEvent(user, Event.LOGIN_FAIL, "password missmatched", ipAddress, hash.signature(), hash.keyId());
            throw new IllegalArgumentException("password is incorrect");
        }
        ;
        HmacDTO session = hmacService.encode(rawDeviceBind+user.getId().toHexString()+username);
        user.setNumberOfInitaiatedOperations(0);
        user.setLockingTime(null);
        userService.saveUser(user);
        logSecurityEvent(user, Event.LOGIN_SUCCESS, null, ipAddress, hash.signature(), hash.keyId());
        return new LoginSuccessResponseDTO(user.getId().toHexString(),user.getUsername(),session.signature(),session.keyId());
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
