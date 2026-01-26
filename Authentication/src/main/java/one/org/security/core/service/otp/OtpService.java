package one.org.security.core.service.otp;

import java.util.Random;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import one.org.security.api.Errors.CustomExceptions.AccountBlockedException;
import one.org.security.api.Errors.CustomExceptions.MailNotSentException;
import one.org.security.api.Errors.CustomExceptions.SmsNotSentException;
import one.org.security.api.Errors.CustomExceptions.UnauthorizedOperationException;
import one.org.security.api.dto.enums.OtpSentMethodEnum;

import java.time.LocalDateTime;


import one.org.security.core.domain.dto.MailDTO;
import one.org.security.core.domain.dto.OtpVerificationDTO;
import one.org.security.core.domain.dto.SmsDTO;
import one.org.security.core.domain.entity.User;
import one.org.security.core.service.Cache.RedisService;
import one.org.security.core.service.Notification.NotificationService;
import one.org.security.core.service.User.UserService;

@Service
public class OtpService {

    @Autowired
    private RedisService redisService;
    @Autowired
    private NotificationService notificationService;
    @Autowired
    private UserService userService;

    public void sendOtp(String username, String target, OtpSentMethodEnum method, String subject) {
        int otp = new Random().nextInt(900000) + 100000;
        redisService.setOtpVerification(new OtpVerificationDTO(username,  otp, target, method, 0));

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

    public void verifyOtp(String username, String otp) {
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
                redisService.setOtpVerification(new OtpVerificationDTO(otpData.username(),
                        otpData.otp(), otpData.to(), otpData.method(), attempts));
            }
            throw new BadCredentialsException("Invalid OTP");
        }
        redisService.deleteOtpVerification(username);
    }

    public void resendOtpSimple(String username, OtpSentMethodEnum expectedMethod) {
        User user = userService.getUserByUsername(username);
        if (user == null) {
            throw new UnauthorizedOperationException("User not found");
        }

        OtpVerificationDTO cachedData = redisService.getOtpVerification(user.getUsername());
        if (cachedData == null) {
            throw new UnauthorizedOperationException("OTP expired or not found. Please initiate flow again.");
        }

        if (cachedData.method() != expectedMethod) {
            throw new UnauthorizedOperationException("Method mismatch for resend");
        }

        boolean error = false;
        if (cachedData.method() == OtpSentMethodEnum.MAIL) {
            error = !notificationService
                    .sendOtpByMail(new MailDTO(cachedData.to(), "Resend OTP", String.valueOf(cachedData.otp())));
        } else if (cachedData.method() == OtpSentMethodEnum.PHONE_NUMBER) {
            error = !notificationService.sendOtpBySMS(new SmsDTO(cachedData.to(), String.valueOf(cachedData.otp())));
        }

        if (error) {
            if (cachedData.method() == OtpSentMethodEnum.MAIL)
                throw new MailNotSentException("error in sending mail");
            else
                throw new SmsNotSentException("error in sending sms");
        }

        // Update cache (timestamp refresh if needed, here just re-setting similar to
        // original code)
        redisService.setOtpVerification(cachedData);
    }
}
