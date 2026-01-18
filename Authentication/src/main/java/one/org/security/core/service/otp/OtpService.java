package one.org.security.core.service.otp;

import java.util.Random;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import one.org.security.api.Errors.CustomExceptions.MailNotSentException;
import one.org.security.api.Errors.CustomExceptions.SmsNotSentException;
import one.org.security.api.Errors.CustomExceptions.UnauthorizedOperationException;
import one.org.security.api.dto.request.ResendOtpRequestDTO;
import one.org.security.core.domain.dto.MailDTO;
import one.org.security.common.dto.OtpVerificationDTO;
import one.org.security.core.domain.dto.SmsDTO;
import one.org.security.common.dto.TokenDTO;
import one.org.security.core.domain.enums.CheckUserExistRequestAvailableEnum;
import one.org.security.common.enums.OtpSentMethodEnum;
import one.org.security.common.enums.TokenPurposeMessageEnum;
import one.org.security.core.service.VerifyUserService;
import one.org.security.common.service.RedisService;
import java.time.LocalDateTime;

import one.org.security.api.Errors.CustomExceptions.AccountBlockedException;
import one.org.security.core.domain.entity.User;
import one.org.security.core.service.SecurityEventService;
import one.org.security.core.service.UserService;
import one.org.security.infrastructure.messaging.NotificationService;

@Service
public class OtpService {

    @Autowired
    private RedisService redisService;
    @Autowired
    private NotificationService notificationService;
    @Autowired
    private VerifyUserService verifyUserService;
    @Autowired
    private UserService userService;
    @Autowired
    private SecurityEventService securityEventService;

    public void sendOtp(String username, String deviceHash, String target, OtpSentMethodEnum method, String subject) {
        int otp = new Random().nextInt(900000) + 100000;
        redisService.setOtpVerification(new OtpVerificationDTO(username, deviceHash, otp, target, method, 0));

        boolean error = false;
        if (method == OtpSentMethodEnum.MAIL) {
            error = !notificationService.sendOtpByMail(new MailDTO(target, subject, String.valueOf(otp)));
        } else {
            error = !notificationService.sendOtpBySMS(new SmsDTO(target, String.valueOf(otp)));
        }

        if (error) {
            redisService.deleteOtpVerification(username);
            if (method == OtpSentMethodEnum.MAIL)
                throw new MailNotSentException("error in sending mail");
            else
                throw new SmsNotSentException("error in sending sms");
        }
    }

    public void verifyOtp(String username, String otp, String deviceHash) {
        OtpVerificationDTO otpData = redisService.getOtpVerification(username);
        if (otpData == null) {
            throw new BadCredentialsException("OTP expired or not found");
        }
        if (!otpData.otp().toString().equals(otp)) {
            int attempts = otpData.attempts() + 1;
            if (attempts > 3) {
                User user = userService.getUserByUsername(username);
                if (user != null) {
                    if (user.getLockingTime() != null
                            && user.getLockingTime().plusHours(6).isAfter(LocalDateTime.now())) {
                        throw new AccountBlockedException("account blocked");
                    }
                    if (user.getNumberOfInitaiatedOperations() < 4) {
                        // Only increment if not already in a high state, or just increment?
                        // User requested: "operation initated count increases by 1"
                        // This acts as a "soft block" trigger in CoreAuthenticationService logic.
                        user.setNumberOfInitaiatedOperations(user.getNumberOfInitaiatedOperations() + 1);
                        if (user.getNumberOfInitaiatedOperations() > 3) {
                            user.setLockingTime(LocalDateTime.now());
                        }
                        userService.saveUser(user);
                    }
                }
                redisService.deleteOtpVerification(username);
                throw new BadCredentialsException("Invalid OTP. Limit exceeded.");
            } else {
                redisService.setOtpVerification(new OtpVerificationDTO(otpData.username(), otpData.deviceHash(),
                        otpData.otp(), otpData.to(), otpData.method(), attempts));
            }
            throw new BadCredentialsException("Invalid OTP");
        }
        if (!otpData.deviceHash().equals(deviceHash)) {
            throw new UnauthorizedOperationException("Device verification failed");
        }
        redisService.deleteOtpVerification(username);
    }

    public void resendOtp(ResendOtpRequestDTO request, String token, String rawDeviceHash) {
        // Note: For resend, we verify against the cached data itself mostly, but here
        // we assume validation checks are done before calling or we pass cached data.
        // Actually, resendOtp logic in original service gets data from redis.
        TokenPurposeMessageEnum purpose = null;
        if (request.purpose() == CheckUserExistRequestAvailableEnum.LOGIN) {
            purpose = TokenPurposeMessageEnum.LOGIN;
        } else if (request.purpose() == CheckUserExistRequestAvailableEnum.FORGET_PASSWORD) {
            purpose = TokenPurposeMessageEnum.FORGET_PASSWORD;
        }
        if (purpose == null) {
            throw new IllegalArgumentException("wrong purpose");
        }
        TokenDTO data = verifyUserService.verifyUser(token, rawDeviceHash, purpose);

        OtpVerificationDTO cachedData = redisService.getOtpVerification(data.subject());

        if (cachedData == null) {
            throw new UnauthorizedOperationException("tokens are invalid or expired");
        }

        if (cachedData.method() == OtpSentMethodEnum.MAIL) {
            if (!notificationService
                    .sendOtpByMail(new MailDTO(cachedData.to(), "resend otp", String.valueOf(cachedData.otp())))) {
                throw new MailNotSentException("error in sending mail");
            }
        } else if (cachedData.method() == OtpSentMethodEnum.PHONE_NUMBER) {
            if (!notificationService.sendOtpBySMS(new SmsDTO(cachedData.to(), String.valueOf(cachedData.otp())))) {
                throw new SmsNotSentException("error in sending sms");
            }
        }

        if (!redisService.setOtpVerification(cachedData)) {
            throw new RuntimeException("failed to cache data");
        }
    }
}
