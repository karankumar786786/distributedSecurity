package one.org.security.api.controller.otp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import one.org.security.api.Errors.CustomExceptions.InvalidSessionException;
import one.org.security.core.service.otp.OtpService;

@RestController
@RequestMapping("/auth")
public class OtpController {

    @Autowired
    private OtpService otpService;

    @GetMapping("/resend-otp/forget-password/backup-email")
    public ResponseEntity<Void> resendOtpForgetPasswordBackupEmail(
            @RequestAttribute("USERNAME") String username,
            @RequestAttribute("FORGET-PASSWORD-SESSION") String forgetPasswordSession
        ) {
            if (forgetPasswordSession == null || forgetPasswordSession.isEmpty()||!"BACKUP-EMAIL".equals(forgetPasswordSession)) {
                throw new InvalidSessionException("invalid sessison");
            } 
        otpService.resendOtpSimple(username, one.org.security.api.dto.enums.OtpSentMethodEnum.MAIL);
        return ResponseEntity.accepted().build();
    }

    @GetMapping("/resend-otp/forget-password/phone-number")
    public ResponseEntity<Void> resendOtpForgetPasswordPhoneNumber(
            @RequestAttribute("USERNAME") String username,
            @RequestAttribute("FORGET-PASSWORD-SESSION") String forgetPasswordSession
        ) {
            if (forgetPasswordSession == null || forgetPasswordSession.isEmpty() || !"PHONE-NUMBER".equals(forgetPasswordSession)) {
                throw new InvalidSessionException("invalid session");
            }
        otpService.resendOtpSimple(username, one.org.security.api.dto.enums.OtpSentMethodEnum.PHONE_NUMBER);
        return ResponseEntity.accepted().build();
    }
}
