package one.org.security.core.service.recovery;

import java.util.Collections;
import java.util.Map;

import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import one.org.security.api.Errors.CustomExceptions.InvalidTokenException;
import one.org.security.api.Errors.CustomExceptions.UnauthorizedOperationException;
import one.org.security.api.dto.request.ForgetPasswordRequestDTO;
import one.org.security.api.dto.request.VerifyForgetPasswordRequestDTO;
import one.org.security.common.dto.OtpVerificationDTO;
import one.org.security.common.dto.TokenDTO;
import one.org.security.core.domain.entity.SecurityEvent;
import one.org.security.core.domain.entity.User;
import one.org.security.common.enums.Event;
import one.org.security.core.domain.enums.ForgetPasswordRequestEnum;
import one.org.security.common.enums.OtpSentMethodEnum;
import one.org.security.common.enums.TokenPurposeMessageEnum;
import one.org.security.core.service.SecurityEventService;
import one.org.security.core.service.UserService;
import one.org.security.core.service.VerifyUserService;
import one.org.security.core.service.otp.OtpService;
import one.org.security.common.service.RedisService;

import one.org.security.infrastructure.config.JwtProperties;
import one.org.security.common.service.JwtService;
import one.org.security.infrastructure.security.filter.EncodingService;

@Service
public class PasswordRecoveryService {

    @Autowired
    private UserService userService;
    @Autowired
    private VerifyUserService verifyUserService;
    @Autowired
    private SecurityEventService securityEventService;
    @Autowired
    private OtpService otpService;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private RedisService redisService;
    @Autowired
    private EncodingService encodingService;
    @Autowired
    private JwtProperties jwtProperties;

    public Map<String, String> forgetPassword(ForgetPasswordRequestDTO request, String tempToken,
            String rawDeviceData) {
        String ipAddress = rawDeviceData.split(":")[1];
        TokenDTO data = verifyTempToken(tempToken, rawDeviceData,TokenPurposeMessageEnum.FORGET_PASSWORD);
        User user = userService.getUserById(new ObjectId(data.id()));

        if (request.option() == ForgetPasswordRequestEnum.BACKUP_EMAIL) {
            handleBackupEmailOtp(user, data.deviceHash(), ipAddress);
        } else if (request.option() == ForgetPasswordRequestEnum.PHONE_NUMBER) {
            handlePhoneNumberOtp(user, data.deviceHash(), ipAddress);
        } else {
            throw new BadCredentialsException("unsupported type option");
        }

        logSecurityEvent(user, Event.FORGET_PASSWORD_INITIATED, null, ipAddress, data.deviceHash(), null);

        TokenDTO newTokenDTO = new TokenDTO(data.subject(), data.id(), data.deviceHash(),
                jwtProperties.getRecoveryExpiration(), data.hmacKeyId(),
                TokenPurposeMessageEnum.FORGET_PASSWORD_VERIFICATION);
        return Collections.singletonMap("token", jwtService.encode(newTokenDTO));
    }

    public Map<String, String> verifyForgetPassword(VerifyForgetPasswordRequestDTO request, String token,
            String rawDeviceData) {
        String ipAddress = rawDeviceData.split(":")[1];
        TokenDTO data = verifyToken(token, rawDeviceData, TokenPurposeMessageEnum.FORGET_PASSWORD_VERIFICATION);
        OtpVerificationDTO otpData = redisService.getOtpVerification(data.subject());
        if (otpData == null) {
            throw new BadCredentialsException("OTP expired or not found");
        }
        if (!otpData.otp().toString().equals(request.otp())) {
            throw new BadCredentialsException("Invalid OTP");
        }
        if (!otpData.deviceHash().equals(data.deviceHash())) {
            throw new UnauthorizedOperationException("Device verification failed");
        }
        User user = userService.getUserById(new ObjectId(data.id()));
        user.setPassword(encodingService.encode(request.password()));
        userService.saveUser(user);
        logSecurityEvent(user, Event.FORGET_PASSWORD_SUCCESS, null, ipAddress, data.deviceHash(), null);
        return Collections.singletonMap("message", "Password changed successfully");
    }

    // --- Helpers ---

    private TokenDTO verifyTempToken(String token, String rawDeviceData,TokenPurposeMessageEnum purpose) {
        return verifyToken(token, rawDeviceData, purpose);
    }

    private TokenDTO verifyToken(String token, String rawDeviceData, TokenPurposeMessageEnum purpose) {
        TokenDTO data = verifyUserService.verifyUser(token, rawDeviceData, purpose);
        if (data == null) {
            throw new InvalidTokenException("Invalid or expired token");
        }
        if (data.purpose() != purpose) {
            throw new UnauthorizedOperationException("Invalid token purpose");
        }
        return data;
    }

    private void handleBackupEmailOtp(User user, String deviceHash, String ipAddress) {
        if (!user.isBackupEmailVerified() || user.getBackupEmail() == null) {
            logSecurityEvent(user, Event.FORGET_PASSWORD_FAIL, "due to non verified backup email", ipAddress,
                    deviceHash, null);
            throw new BadCredentialsException("backup email is not verified");
        }
        otpService.sendOtp(user.getUsername(), deviceHash, user.getBackupEmail(), OtpSentMethodEnum.MAIL,
                "forget-password");
    }

    private void handlePhoneNumberOtp(User user, String deviceHash, String ipAddress) {
        if (!user.isPhoneNumberVerified() || user.getPhoneNumber() == null) {
            logSecurityEvent(user, Event.FORGET_PASSWORD_FAIL, "due to non verified phone number", ipAddress,
                    deviceHash, null);
            throw new BadCredentialsException("phone number is not verified");
        }
        otpService.sendOtp(user.getUsername(), deviceHash, user.getPhoneNumber(), OtpSentMethodEnum.PHONE_NUMBER, null);
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
