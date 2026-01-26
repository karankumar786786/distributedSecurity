package one.org.security.api.controller.recovery;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import one.org.security.api.dto.request.VerifyForgetPasswordRequestDTO;
import one.org.security.core.service.recovery.PasswordRecoveryService;

@RestController
@RequestMapping("/init/forget-password")
public class RecoveryController {

        @Autowired
        private PasswordRecoveryService passwordRecoveryService;

        @GetMapping("/backup-email")
        public ResponseEntity<Void> initForgetPasswordBackupEmail(
                        @RequestAttribute("USERNAME") String username,
                        @RequestAttribute("INIT-SESSION") String initSession,
                        @RequestAttribute("IP-ADDRESS") String ipAddress,
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind
                ) {

                passwordRecoveryService.initBackupEmail(username, rawDeviceBind, ipAddress);
                ResponseCookie forgetPasswordCookie = ResponseCookie.from("FORGET-PASSWORD-SESSION", "BACKUP_EMAIL")
                                .httpOnly(true)
                                .secure(false)
                                .path("/")
                                .sameSite("Lax")
                                .maxAge(300L)
                                .build();

                return ResponseEntity.accepted()
                                .header(org.springframework.http.HttpHeaders.SET_COOKIE,
                                                forgetPasswordCookie.toString())
                                .build();
        }

        @PostMapping("/backup-email/complete")
        public ResponseEntity<Void> initForgetPasswordBackupEmailComplete(
                        @Validated @RequestBody VerifyForgetPasswordRequestDTO verifyForgetRequest,
                        @RequestAttribute("USERNAME") String username,
                        @RequestAttribute("INIT-SESSION") String initSession,
                        @RequestAttribute("IP-ADDRESS") String ipAddress,
                        @RequestAttribute("FORGET-PASSWORD-SESSION") String forgetPasswordSession,
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind
                ) {

                passwordRecoveryService.verifyForgetPassword(verifyForgetRequest, username,
                                rawDeviceBind, ipAddress);

                return ResponseEntity.accepted().build();
        }

        @GetMapping("/phone-number")
        public ResponseEntity<Void> initForgetPasswordPhoneNumber(
                        @RequestAttribute("USERNAME") String username,
                        @RequestAttribute("INIT-SESSION") String initSession,
                        @RequestAttribute("IP-ADDRESS") String ipAddress,
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind
                ) {

                passwordRecoveryService.initPhoneNumber(username, rawDeviceBind, ipAddress);

                ResponseCookie forgetPasswordCookie = ResponseCookie.from("FORGET-PASSWORD-SESSION", "PHONE_NUMBER")
                                .httpOnly(true)
                                .secure(false)
                                .path("/")
                                .sameSite("Lax")
                                .maxAge(300L)
                                .build();

                return ResponseEntity.accepted()
                                .header(org.springframework.http.HttpHeaders.SET_COOKIE,
                                                forgetPasswordCookie.toString())
                                .build();
        }

        @PostMapping("/phone-number/complete")
        public ResponseEntity<Void> completeForgetPassword(
                        @Validated @RequestBody VerifyForgetPasswordRequestDTO verifyForgetRequest,
                        @RequestAttribute("USERNAME") String username,
                        @RequestAttribute("INIT-SESSION") String initSession,
                        @RequestAttribute("IP-ADDRESS") String ipAddress,
                        @RequestAttribute("FORGET-PASSWORD-SESSION") String forgetPasswordSession,
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind
                ) {

                passwordRecoveryService.verifyForgetPassword(verifyForgetRequest, username,
                                rawDeviceBind, ipAddress);

                return ResponseEntity.accepted().build();
        }

        @GetMapping("/resend-otp/backup-email")
        public ResponseEntity<Void> resendOtpBackupEmail(
                        @RequestAttribute("USERNAME") String username,
                        @RequestAttribute("INIT-SESSION") String initSession,
                        @RequestAttribute("IP-ADDRESS") String ipAddress,
                        @RequestAttribute("FORGET-PASSWORD-SESSION") String forgetPasswordSession,
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind
                ) {

                passwordRecoveryService.initBackupEmail(username, rawDeviceBind, ipAddress);

                return ResponseEntity.accepted().build();
        }

        @GetMapping("/resend-otp/phone-number")
        public ResponseEntity<Void> resendOtpPhoneNumber(
                        @RequestAttribute("USERNAME") String username,
                        @RequestAttribute("INIT-SESSION") String initSession,
                        @RequestAttribute("IP-ADDRESS") String ipAddress,
                        @RequestAttribute("FORGET-PASSWORD-SESSION") String forgetPasswordSession,
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind
                ) {

                passwordRecoveryService.initPhoneNumber(username, rawDeviceBind, ipAddress);

                return ResponseEntity.accepted().build();
        }

        
}
