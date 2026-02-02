package one.org.security.api.controller.recovery;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import one.org.security.api.Errors.CustomExceptions.InvalidSessionException;
import one.org.security.api.dto.request.VerifyForgetPasswordRequestDTO;
import one.org.security.api.dto.response.RecoveryTokenResponseDTO;
import one.org.security.core.service.auth.InitSessionService;
import one.org.security.core.service.auth.InitSessionService.RecoveryTokenData;
import one.org.security.core.service.recovery.PasswordRecoveryService;

@RestController
@RequestMapping("/init/forget-password")
public class RecoveryController {

        @Autowired
        private PasswordRecoveryService passwordRecoveryService;

        @Autowired
        private InitSessionService initSessionService;

        /**
         * Initiate password recovery via backup email.
         * Returns recovery token instead of cookie.
         */
        @GetMapping("/backup-email")
        public ResponseEntity<RecoveryTokenResponseDTO> initForgetPasswordBackupEmail(
                        @RequestAttribute("USERNAME") String username,
                        @RequestAttribute("USER-ID") String userId,
                        @RequestAttribute("INIT-SESSION") String initSession,
                        @RequestAttribute("IP-ADDRESS") String ipAddress,
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {

                passwordRecoveryService.initBackupEmail(username, rawDeviceBind, ipAddress);

                String recoveryToken = initSessionService.generateRecoveryToken(userId, "BACKUP_EMAIL");

                return ResponseEntity.accepted()
                                .header("X-Recovery-Token", recoveryToken)
                                .body(new RecoveryTokenResponseDTO(recoveryToken, "BACKUP_EMAIL"));
        }

        /**
         * Complete password recovery via backup email.
         * Expects recovery token in X-Recovery-Token header.
         */
        @PostMapping("/backup-email/complete")
        public ResponseEntity<Void> initForgetPasswordBackupEmailComplete(
                        @Validated @RequestBody VerifyForgetPasswordRequestDTO verifyForgetRequest,
                        @RequestAttribute("USERNAME") String username,
                        @RequestHeader(value = "X-Recovery-Token", required = true) String recoveryToken,
                        @RequestAttribute("IP-ADDRESS") String ipAddress,
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {

                // Validate recovery token
                RecoveryTokenData tokenData = initSessionService.validateRecoveryToken(recoveryToken);
                if (tokenData == null || !"BACKUP_EMAIL".equals(tokenData.method())) {
                        throw new InvalidSessionException("Invalid or expired recovery token");
                }

                passwordRecoveryService.verifyForgetPassword(verifyForgetRequest, username,
                                rawDeviceBind, ipAddress);

                return ResponseEntity.accepted().build();
        }

        /**
         * Initiate password recovery via phone number.
         * Returns recovery token instead of cookie.
         */
        @GetMapping("/phone-number")
        public ResponseEntity<RecoveryTokenResponseDTO> initForgetPasswordPhoneNumber(
                        @RequestAttribute("USERNAME") String username,
                        @RequestAttribute("USER-ID") String userId,
                        @RequestAttribute("INIT-SESSION") String initSession,
                        @RequestAttribute("IP-ADDRESS") String ipAddress,
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {

                passwordRecoveryService.initPhoneNumber(username, rawDeviceBind, ipAddress);

                String recoveryToken = initSessionService.generateRecoveryToken(userId, "PHONE_NUMBER");

                return ResponseEntity.accepted()
                                .header("X-Recovery-Token", recoveryToken)
                                .body(new RecoveryTokenResponseDTO(recoveryToken, "PHONE_NUMBER"));
        }

        /**
         * Complete password recovery via phone number.
         * Expects recovery token in X-Recovery-Token header.
         */
        @PostMapping("/phone-number/complete")
        public ResponseEntity<Void> completeForgetPassword(
                        @Validated @RequestBody VerifyForgetPasswordRequestDTO verifyForgetRequest,
                        @RequestAttribute("USERNAME") String username,
                        @RequestHeader(value = "X-Recovery-Token", required = true) String recoveryToken,
                        @RequestAttribute("IP-ADDRESS") String ipAddress,
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {

                // Validate recovery token
                RecoveryTokenData tokenData = initSessionService.validateRecoveryToken(recoveryToken);
                if (tokenData == null || !"PHONE_NUMBER".equals(tokenData.method())) {
                        throw new InvalidSessionException("Invalid or expired recovery token");
                }

                passwordRecoveryService.verifyForgetPassword(verifyForgetRequest, username,
                                rawDeviceBind, ipAddress);

                return ResponseEntity.accepted().build();
        }

        /**
         * Resend OTP for backup email recovery.
         * Expects recovery token in X-Recovery-Token header.
         */
        @GetMapping("/resend-otp/backup-email")
        public ResponseEntity<Void> resendOtpBackupEmail(
                        @RequestAttribute("USERNAME") String username,
                        @RequestHeader(value = "X-Recovery-Token", required = true) String recoveryToken,
                        @RequestAttribute("IP-ADDRESS") String ipAddress,
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {

                // Validate recovery token
                RecoveryTokenData tokenData = initSessionService.validateRecoveryToken(recoveryToken);
                if (tokenData == null || !"BACKUP_EMAIL".equals(tokenData.method())) {
                        throw new InvalidSessionException("Invalid or expired recovery token");
                }

                passwordRecoveryService.initBackupEmail(username, rawDeviceBind, ipAddress);

                return ResponseEntity.accepted().build();
        }

        /**
         * Resend OTP for phone number recovery.
         * Expects recovery token in X-Recovery-Token header.
         */
        @GetMapping("/resend-otp/phone-number")
        public ResponseEntity<Void> resendOtpPhoneNumber(
                        @RequestAttribute("USERNAME") String username,
                        @RequestHeader(value = "X-Recovery-Token", required = true) String recoveryToken,
                        @RequestAttribute("IP-ADDRESS") String ipAddress,
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {

                // Validate recovery token
                RecoveryTokenData tokenData = initSessionService.validateRecoveryToken(recoveryToken);
                if (tokenData == null || !"PHONE_NUMBER".equals(tokenData.method())) {
                        throw new InvalidSessionException("Invalid or expired recovery token");
                }

                passwordRecoveryService.initPhoneNumber(username, rawDeviceBind, ipAddress);

                return ResponseEntity.accepted().build();
        }
}
