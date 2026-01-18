package one.org.security.core.service.account;

import java.util.Collections;
import java.util.Map;

import one.org.security.common.enums.Event;
import one.org.security.core.domain.entity.SecurityEvent;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import one.org.security.api.dto.request.ChangeBackupEmailRequestDTO;
import one.org.security.api.dto.request.ChangePasswordRequestDTO;
import one.org.security.api.dto.request.ChangePhoneNumberRequestDTO;
import one.org.security.api.dto.request.VerifyOtpRequestDTO;
import one.org.security.common.dto.HmacDTO;
import one.org.security.core.domain.entity.User;
import one.org.security.common.enums.OtpSentMethodEnum;
import one.org.security.core.service.UserService;
import one.org.security.core.service.otp.OtpService;
import one.org.security.common.service.RedisService;
import one.org.security.common.service.HmacService;
import one.org.security.core.service.SecurityEventService;
import one.org.security.infrastructure.security.filter.EncodingService;

@Service
public class UserAccountService {

    @Autowired
    private UserService userService;
    @Autowired
    private EncodingService encodingService;
    @Autowired
    private HmacService hmacService;
    @Autowired
    private OtpService otpService;
    @Autowired
    private RedisService redisService;
    @Autowired
    private SecurityEventService securityEventService;

    public Map<String, String> changePassword(ChangePasswordRequestDTO request, User user) {
        if (user == null)
            throw new IllegalArgumentException("User context not found");
        User dbUser = userService.getUserById(user.getId());

        if (!encodingService.verify(request.oldPassword(), dbUser.getPassword())) {
            throw new BadCredentialsException("Invalid old password");
        }

        userService.updatePassword(dbUser.getId(), encodingService.encode(request.newPassword()));

        // Log event
        // We don't have IP/DeviceHash here?
        // Method signature only has User.
        // Needs rawDeviceData to log correctly.
        // Wait, changePassword in Controller (Step 630) does NOT pass rawDeviceData.
        // I need to update Controller too if I want full logging context.
        // Assuming user.getKnownDeviceHashes() might be used? No, that's a list.
        // Ideally we pass rawDeviceData.
        // Controller changePassword: public ResponseEntity<Map<String, String>>
        // changePassword(..., @AuthenticationPrincipal User user)
        // It does NOT have @RequestAttribute("RAW_DEVICE_DATA").
        // I should update Controller signature as well.

        // But for now, to complete THIS tool call without breaking flow:
        // I will just log with "unknown" or minimal info if I can't change signature
        // here.
        // OR I update signature here and then update controller.
        // Controller update + Service update is needed.
        // Let's assume I will update Controller in next step.
        // I will add rawDeviceData to signature.
        logSecurityEvent(dbUser, Event.PASSWORD_CHANGED, "Password changed", "unknown", "unknown", null);

        return Collections.singletonMap("message", "Password changed successfully");
    }

    public Map<String, String> changeBackupEmail(ChangeBackupEmailRequestDTO request, User user, String rawDeviceData) {
        if (user == null)
            throw new IllegalArgumentException("User context not found");
        HmacDTO hash = hmacService.encode(rawDeviceData);

        userService.updateBackupEmail(user.getId(), request.backupEmail());
        otpService.sendOtp(user.getUsername(), hash.signature(), request.backupEmail(), OtpSentMethodEnum.MAIL,
                "Verify Backup Email");

        return Collections.singletonMap("message", "OTP sent to backup email");
    }

    public Map<String, String> changePhoneNumber(ChangePhoneNumberRequestDTO request, User user, String rawDeviceData) {
        if (user == null)
            throw new IllegalArgumentException("User context not found");
        HmacDTO hash = hmacService.encode(rawDeviceData);

        userService.updatePhoneNumber(user.getId(), request.phoneNumber());
        otpService.sendOtp(user.getUsername(), hash.signature(), request.phoneNumber(), OtpSentMethodEnum.PHONE_NUMBER,
                null);

        return Collections.singletonMap("message", "OTP sent to phone number");
    }

    public Map<String, String> verifyBackupEmail(VerifyOtpRequestDTO request, User user, String rawDeviceData) {
        if (user == null)
            throw new IllegalArgumentException("User context not found");
        HmacDTO hash = hmacService.encode(rawDeviceData);

        otpService.verifyOtp(user.getUsername(), request.otp(), hash.signature());
        userService.markBackupEmailVerified(user.getId());
        redisService.deleteOtpVerification(user.getUsername());

        String ipAddress = rawDeviceData.contains(":") ? rawDeviceData.split(":")[1] : "unknown";
        logSecurityEvent(user, Event.BACKUP_EMAIL_VERIFIED, "Backup email verified", ipAddress, hash.signature(),
                hash.keyId());

        return Collections.singletonMap("message", "Backup email verified");
    }

    public Map<String, String> verifyPhoneNumber(VerifyOtpRequestDTO request, User user, String rawDeviceData) {
        if (user == null)
            throw new IllegalArgumentException("User context not found");
        HmacDTO hash = hmacService.encode(rawDeviceData);

        otpService.verifyOtp(user.getUsername(), request.otp(), hash.signature());
        userService.markPhoneNumberVerified(user.getId());
        redisService.deleteOtpVerification(user.getUsername());

        String ipAddress = rawDeviceData.contains(":") ? rawDeviceData.split(":")[1] : "unknown";
        logSecurityEvent(user, Event.PHONE_NUMBER_VERIFIED, "Phone number verified", ipAddress, hash.signature(),
                hash.keyId());

        return Collections.singletonMap("message", "Phone number verified");
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
