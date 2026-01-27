package one.org.security.core.service.recovery;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import one.org.security.api.Errors.CustomExceptions.UserNotFoundException;
import one.org.security.api.dto.enums.OtpSentMethodEnum;
import one.org.security.api.dto.request.VerifyForgetPasswordRequestDTO;
import one.org.security.common.Hmac.HmacDTO;
import one.org.security.common.Hmac.HmacService;
import one.org.security.common.PasswordEncoding.EncodingService;
import one.org.security.common.enums.Event;
import one.org.security.core.domain.dto.OtpVerificationDTO;
import one.org.security.core.domain.entity.SecurityEvent;
import one.org.security.core.domain.entity.User;
import one.org.security.core.service.Cache.RedisService;
import one.org.security.core.service.SecurityEvent.SecurityEventService;
import one.org.security.core.service.User.UserService;
import one.org.security.core.service.otp.OtpService;

@Service
public class PasswordRecoveryService {

    @Autowired
    private UserService userService;
    @Autowired
    private RedisService redisService;
    @Autowired
    private EncodingService encodingService;
    @Autowired
    private OtpService otpService;
    @Autowired
    private SecurityEventService securityEventService;
    @Autowired
    private HmacService hmacService;

    public void initBackupEmail(String username, String rawDeviceBind, String ipAddress) {
        User user = userService.getUserByUsername(username);
        if (user == null) {
            // Return random UUID even if user not found to prevent timing enumeration,
            // but for now strict:
            throw new UserNotFoundException("User not found");
        }
        ;
        HmacDTO hash = hmacService.encode(rawDeviceBind);
        handleBackupEmailOtp(user, hash.signature(), hash.keyId(), ipAddress);
        logSecurityEvent(user, Event.FORGET_PASSWORD_INITIATED, null, ipAddress, hash.signature(), hash.keyId());
        return;
    }

    public void initPhoneNumber(String username, String rawDeviceBind, String ipAddress) {
        User user = userService.getUserByUsername(username);
        if (user == null) {
            throw new UserNotFoundException("User not found");
        }
        HmacDTO hash = hmacService.encode(rawDeviceBind);
        handlePhoneNumberOtp(user, hash.signature(), hash.keyId(), ipAddress);
        logSecurityEvent(user, Event.FORGET_PASSWORD_INITIATED, null, ipAddress, hash.signature(), hash.keyId());
        return;
    }

    public void verifyForgetPassword(VerifyForgetPasswordRequestDTO request, String username,
            String rawDeviceBind, String ipAddress) {
        User user = userService.getUserByUsername(username);
        if (user == null) {
            throw new UserNotFoundException("User not found");
        }

        OtpVerificationDTO otpData = redisService.getOtpVerification(user.getUsername());
        if (otpData == null) {
            throw new BadCredentialsException("OTP expired or not found");
        }
        if (!otpData.otp().toString().equals(request.otp())) {
            throw new BadCredentialsException("Invalid OTP");
        }
        HmacDTO hash = hmacService.encode(rawDeviceBind);
        user.setPassword(encodingService.encode(request.password()));
        userService.saveUser(user);
        logSecurityEvent(user, Event.FORGET_PASSWORD_SUCCESS, null, ipAddress, hash.signature(), hash.keyId());
        redisService.deleteOtpVerification(user.getUsername());
    }

    // --- Helpers ---

    private void handleBackupEmailOtp(User user, String deviceHash, String deviceHashKeyId, String ipAddress) {
        if (!user.isBackupEmailVerified() || user.getBackupEmail() == null) {
            logSecurityEvent(user, Event.FORGET_PASSWORD_FAIL, "due to non verified backup email", ipAddress,
                    deviceHash, deviceHashKeyId);
            throw new BadCredentialsException("backup email is not verified");
        }
        otpService.sendOtp(user.getUsername(), user.getBackupEmail(), OtpSentMethodEnum.MAIL,
                "forget-password");
    }

    private void handlePhoneNumberOtp(User user, String deviceHash, String deviceHashKeyId, String ipAddress) {
        if (!user.isPhoneNumberVerified() || user.getPhoneNumber() == null) {
            logSecurityEvent(user, Event.FORGET_PASSWORD_FAIL, "due to non verified phone number", ipAddress,
                    deviceHash, deviceHashKeyId);
            throw new BadCredentialsException("phone number is not verified");
        }
        otpService.sendOtp(user.getUsername(), user.getPhoneNumber(), OtpSentMethodEnum.PHONE_NUMBER,
                "forget-password");
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
