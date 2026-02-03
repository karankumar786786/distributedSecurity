package one.org.security.core.service.account;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import one.org.security.api.dto.enums.OtpSentMethodEnum;
import one.org.security.api.dto.request.ChangeBackupEmailRequestDTO;
import one.org.security.api.dto.request.ChangePasswordRequestDTO;
import one.org.security.api.dto.request.ChangePhoneNumberRequestDTO;
import one.org.security.api.dto.request.VerifyOtpRequestDTO;
import one.org.security.common.PasswordEncoding.EncodingService;
import one.org.security.common.enums.Event;
import one.org.security.core.domain.entity.SecurityEvent;
import one.org.security.core.domain.entity.User;
import one.org.security.core.service.otp.OtpService;
import one.org.security.core.service.Cache.RedisService;
import one.org.security.core.service.SecurityEvent.SecurityEventService;
import one.org.security.core.service.User.UserService;

@Service
public class UserAccountService {

    @Autowired
    private UserService userService;
    @Autowired
    private EncodingService encodingService;
    @Autowired
    private OtpService otpService;
    @Autowired
    private RedisService redisService;
    @Autowired
    private SecurityEventService securityEventService;

    public void changePassword(ChangePasswordRequestDTO request, User user, String ipAddress, String deviceHash,
            String deviceHashKeyId) {
        if (user == null)
            throw new IllegalArgumentException("User context not found");
        User dbUser = userService.getUserById(user.getId());
        if (!encodingService.verify(request.oldPassword(), dbUser.getPassword())) {
            throw new BadCredentialsException("Invalid old password");
        }
        userService.updatePassword(dbUser.getId(), encodingService.encode(request.newPassword()));
        logSecurityEvent(dbUser, Event.PASSWORD_CHANGED, "Password changed", ipAddress, deviceHash, deviceHashKeyId);
        return;
    }

    public void changeBackupEmail(ChangeBackupEmailRequestDTO request, User user, String deviceHash,
            String deviceHashKeyId, String ipAddress) {
        if (user == null)
            throw new IllegalArgumentException("User context not found");
        userService.updateBackupEmail(user.getId(), request.backupEmail());
        otpService.sendOtp(user.getUsername(), request.backupEmail(), OtpSentMethodEnum.MAIL,
                "Verify Backup Email");
        return;
    }

    public void changePhoneNumber(ChangePhoneNumberRequestDTO request, User user, String deviceHash,
            String deviceHashKeyId, String ipAddress) {
        if (user == null)
            throw new IllegalArgumentException("User context not found");
        userService.updatePhoneNumber(user.getId(), request.phoneNumber());
        otpService.sendOtp(user.getUsername(), request.phoneNumber(), OtpSentMethodEnum.PHONE_NUMBER,
                null);
        return;
    }

    public void verifyBackupEmail(VerifyOtpRequestDTO request, User user, String deviceHash, String deviceHashKeyId,
            String ipAddress) {
        if (user == null)
            throw new IllegalArgumentException("User context not found");
        otpService.verifyOtp(user.getUsername(), request.otp());
        userService.markBackupEmailVerified(user.getId());
        redisService.deleteOtpVerification(user.getUsername());

        logSecurityEvent(user, Event.BACKUP_EMAIL_VERIFIED, "Backup email verified", ipAddress, deviceHash,
                deviceHashKeyId);
        return;
    }

    public void verifyPhoneNumber(VerifyOtpRequestDTO request, User user, String deviceHash, String deviceHashKeyId,
            String ipAddress) {
        if (user == null)
            throw new IllegalArgumentException("User context not found");
        otpService.verifyOtp(user.getUsername(), request.otp());
        userService.markPhoneNumberVerified(user.getId());
        redisService.deleteOtpVerification(user.getUsername());
        logSecurityEvent(user, Event.PHONE_NUMBER_VERIFIED, "Phone number verified", ipAddress, deviceHash,
                deviceHashKeyId);
        return;
    }

    public void resendOtpForBackupEmail(User user, String deviceHash, String deviceHashKeyId, String ipAddress) {
        if (user == null)
            throw new IllegalArgumentException("User context not found");

        // Ensure user has a backup email set
        User dbUser = userService.getUserById(user.getId());
        if (dbUser.getBackupEmail() == null || dbUser.getBackupEmail().isEmpty()) {
            throw new IllegalArgumentException("No backup email set for user");
        }

        otpService.sendOtp(user.getUsername(), dbUser.getBackupEmail(), OtpSentMethodEnum.MAIL,
                "Verify Backup Email");
        return;
    }

    public void resendOtpForPhoneNumber(User user, String deviceHash, String deviceHashKeyId, String ipAddress) {
        if (user == null)
            throw new IllegalArgumentException("User context not found");

        // Ensure user has a phone number set
        User dbUser = userService.getUserById(user.getId());
        if (dbUser.getPhoneNumber() == null || dbUser.getPhoneNumber().isEmpty()) {
            throw new IllegalArgumentException("No phone number set for user");
        }

        otpService.sendOtp(user.getUsername(), dbUser.getPhoneNumber(), OtpSentMethodEnum.PHONE_NUMBER,
                null);
        return;
    }

    public void deleteAccount(User user, String ipAddress, String deviceHash, String deviceHashKeyId) {
        userService.deleteByUsername(user.getUsername());
        logSecurityEvent(user, Event.ACCOUNT_DELETED, "User deleted account", ipAddress, deviceHash, deviceHashKeyId);
    }

    public void logout(User user, String ipAddress, String deviceHash, String deviceHashKeyId) {
        logSecurityEvent(user, Event.LOGOUT, "User logged out", ipAddress, deviceHash, deviceHashKeyId);
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
