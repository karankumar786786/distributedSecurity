package one.org.security.api.controller.account;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;

import one.org.security.api.dto.request.ChangeBackupEmailRequestDTO;
import one.org.security.api.dto.request.ChangePasswordRequestDTO;
import one.org.security.api.dto.request.ChangePhoneNumberRequestDTO;
import one.org.security.api.dto.request.FidoCompleteRegisterRequestDTO;
import one.org.security.api.dto.request.VerifyOtpRequestDTO;
import one.org.security.api.dto.response.FidoInitResponseDTO;
import one.org.security.common.Hmac.HmacDTO;
import one.org.security.common.Hmac.HmacService;
import one.org.security.core.domain.entity.User;
import one.org.security.core.service.auth.FidoRegistrationService;
import one.org.security.core.service.User.UserService;
import one.org.security.core.service.account.UserAccountService;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;

@RestController
@RequestMapping("/account")
public class AccountController {


    @Autowired
    private UserAccountService userAccountService;

    @Autowired
    private FidoRegistrationService fidoRegistrationService;

    @Autowired
    private UserService userService;

    @Autowired
    private HmacService hmacService;

    @PostMapping("/change-password")
    public ResponseEntity<Void> changePassword(
            @Validated @RequestBody ChangePasswordRequestDTO request,
            @AuthenticationPrincipal User user,
            @RequestAttribute("IP-ADDRESS") String ipAddress,
            @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {

        /**
         * This checks user exist from userId if user dont exist thows error
         */
        User userFromDb = userService.getUserById(user.getId());
        // creating hmac from raw device bind
        HmacDTO hash = hmacService.encode(rawDeviceBind);
        // this service will change password if all is ok then
        userAccountService.changePassword(request, userFromDb, ipAddress, hash.signature(), hash.keyId());
        return new ResponseEntity<>(HttpStatus.ACCEPTED);
    }

    @PostMapping("/change-backup-email")
    public ResponseEntity<Void> changeBackupEmail(
            @Validated @RequestBody ChangeBackupEmailRequestDTO request,
            @AuthenticationPrincipal User user,
            @RequestAttribute("IP-ADDRESS") String ipAddress,
            @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {
                // similarly check in db with userid throws error if user not found then
        User userFromDb = userService.getUserById(user.getId());
        // creating device hash from the raw device bind
        HmacDTO hash = hmacService.encode(rawDeviceBind);
        // change backup email if everything is ok then
        userAccountService.changeBackupEmail(request, userFromDb, hash.signature(), hash.keyId(), ipAddress);
        return new ResponseEntity<>(HttpStatus.ACCEPTED);
    }

    @PostMapping("/change-phone-number")
    public ResponseEntity<Map<String, String>> changePhoneNumber(
            @Validated @RequestBody ChangePhoneNumberRequestDTO request,
            @AuthenticationPrincipal User user,
            @RequestAttribute("IP-ADDRESS") String ipAddress,
            @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {
                // similarly check in db with userid throws error if user not found then
        User userFromDb = userService.getUserById(user.getId());
        // creating device hash from the raw device bind
        HmacDTO hash = hmacService.encode(rawDeviceBind);
        // change the phone number if all ok then 
        userAccountService.changePhoneNumber(request, userFromDb, hash.signature(), hash.keyId(), ipAddress);
        return new ResponseEntity<>(HttpStatus.ACCEPTED);
    }

    @PostMapping("/verify-backup-email")
    public ResponseEntity<Map<String, String>> verifyBackupEmail(
            @Validated @RequestBody VerifyOtpRequestDTO request,
            @AuthenticationPrincipal User user,
            @RequestAttribute("IP-ADDRESS") String ipAddress,
            @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {
                // similarly check in db with userid throws error if user not found then
        User userFromDb = userService.getUserById(user.getId());
         // creating device hash from the raw device bind
        HmacDTO hash = hmacService.encode(rawDeviceBind);
        // verify backup email if everything is ok
        userAccountService.verifyBackupEmail(request, userFromDb, hash.signature(), hash.keyId(), ipAddress);
        return new ResponseEntity<>(HttpStatus.ACCEPTED);
    }

    @PostMapping("/verify-phone-number")
    public ResponseEntity<Void> verifyPhoneNumber(
            @Validated @RequestBody VerifyOtpRequestDTO request,
            @AuthenticationPrincipal User user,
            @RequestAttribute("IP-ADDRESS") String ipAddress,
            @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {
            // similarly check in db with userid throws error if user not found then
        User userFromDb = userService.getUserById(user.getId());
         // creating device hash from the raw device bind
        HmacDTO hash = hmacService.encode(rawDeviceBind);
        // verify phone number if everything is ok
        userAccountService.verifyPhoneNumber(request, userFromDb, hash.signature(), hash.keyId(), ipAddress);
        return new ResponseEntity<>(HttpStatus.ACCEPTED);
    }

    @GetMapping("/resend-otp/verify/backup-email")
    public ResponseEntity<Void> resendOtpVerifyBackupEmail(
            @AuthenticationPrincipal User user,
            @RequestAttribute("IP-ADDRESS") String ipAddress,
            @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {
                // similarly check in db with userid throws error if user not found then
        User userFromDb = userService.getUserById(user.getId());
         // creating device hash from the raw device bind
        HmacDTO hash = hmacService.encode(rawDeviceBind);
        // resend otp if everything is ok
        userAccountService.resendOtpForBackupEmail(userFromDb, hash.signature(), hash.keyId(), ipAddress);
        return new ResponseEntity<>(HttpStatus.ACCEPTED);
    }

    @GetMapping("/resend-otp/verify/phone-number")
    public ResponseEntity<Void> resendOtpVerifyPhoneNumber(
            @AuthenticationPrincipal User user,
            @RequestAttribute("IP-ADDRESS") String ipAddress,
            @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {
                // similarly check in db with userid throws error if user not found then
        User userFromDb = userService.getUserById(user.getId());
         // creating device hash from the raw device bind
        HmacDTO hash = hmacService.encode(rawDeviceBind);
        // resend otp if everything is ok
        userAccountService.resendOtpForPhoneNumber(userFromDb, hash.signature(), hash.keyId(), ipAddress);
        return new ResponseEntity<>(HttpStatus.ACCEPTED);
    }

    @PatchMapping("/fido/register/init")
    public ResponseEntity<FidoInitResponseDTO> initFidoRegister(
            @AuthenticationPrincipal User user,
            @RequestAttribute("IP-ADDRESS") String ipAddress,
            @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind)
            throws JsonProcessingException {
                // similarly check in db with userid throws error if user not found then
        User userFromDb = userService.getUserById(user.getId());
        // this will create option to fido registration
        String response = fidoRegistrationService.initiateRegistration(userFromDb);
        return new ResponseEntity<>(new FidoInitResponseDTO(response), HttpStatus.OK);
    }

    @PostMapping("/fido/register/complete")
    public ResponseEntity<Void> completeFidoRegister(
            @Validated @RequestBody FidoCompleteRegisterRequestDTO request,
            @AuthenticationPrincipal User user,
            @RequestAttribute("IP-ADDRESS") String ipAddress,
            @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {
                // complete the fido registration
        fidoRegistrationService.finishRegistration(user.getId().toHexString(), request.getResponse());
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @DeleteMapping("/delete-account")
    public ResponseEntity<Void> deleteAccount(
            @AuthenticationPrincipal User user,
            @RequestAttribute("IP-ADDRESS") String ipAddress,
            @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {
                //  creating device hash from raw device bind
        HmacDTO hash = hmacService.encode(rawDeviceBind);

                // delet account if everything is ok
        userAccountService.deleteAccount(user, ipAddress, hash.signature(), hash.keyId());
        // No cookie to clear - JWT is client-side only
        return ResponseEntity.accepted().build();
    }

    @PatchMapping("/logout")
    public ResponseEntity<Void> logout(
            @AuthenticationPrincipal User user,
            @RequestAttribute("IP-ADDRESS") String ipAddress,
            @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {
                //  creating device hash from raw device bind
        HmacDTO hash = hmacService.encode(rawDeviceBind);
        if (user != null) {
            userAccountService.logout(user, ipAddress, hash.signature(), hash.keyId());
        }
        // No cookie to clear - JWT is client-side only
        // Client should discard the token from storage
        return ResponseEntity.ok().build();
    }

}
