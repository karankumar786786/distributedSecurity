package one.org.security.core.service.account;

import java.util.Collections;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import one.org.security.api.dto.request.ChangeBackupEmailRequestDTO;
import one.org.security.api.dto.request.ChangePasswordRequestDTO;
import one.org.security.api.dto.request.ChangePhoneNumberRequestDTO;
import one.org.security.api.dto.request.VerifyOtpRequestDTO;
import one.org.security.core.domain.dto.HmacDTO;
import one.org.security.core.domain.entity.User;
import one.org.security.core.domain.enums.OtpSentMethodEnum;
import one.org.security.core.service.UserService;
import one.org.security.core.service.otp.OtpService;
import one.org.security.infrastructure.cache.RedisService;
import one.org.security.infrastructure.security.HmacService;
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

    public Map<String, String> changePassword(ChangePasswordRequestDTO request, User user) {
        if (user == null)
            throw new IllegalArgumentException("User context not found");
        User dbUser = userService.getUserById(user.getId());

        if (!encodingService.verify( request.oldPassword(),dbUser.getPassword())) {
            throw new BadCredentialsException("Invalid old password");
        }

        userService.updatePassword(dbUser.getId(), encodingService.encode(request.newPassword()));
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

        return Collections.singletonMap("message", "Backup email verified");
    }

    public Map<String, String> verifyPhoneNumber(VerifyOtpRequestDTO request, User user, String rawDeviceData) {
        if (user == null)
            throw new IllegalArgumentException("User context not found");
        HmacDTO hash = hmacService.encode(rawDeviceData);

        otpService.verifyOtp(user.getUsername(), request.otp(), hash.signature());
        userService.markPhoneNumberVerified(user.getId());
        redisService.deleteOtpVerification(user.getUsername());

        return Collections.singletonMap("message", "Phone number verified");
    }
}
