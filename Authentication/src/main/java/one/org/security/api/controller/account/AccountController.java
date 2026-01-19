package one.org.security.api.controller.account;

import java.util.Map;

import org.bson.types.ObjectId;
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

import one.org.security.api.dto.request.ChangeBackupEmailRequestDTO;
import one.org.security.api.dto.request.ChangePasswordRequestDTO;
import one.org.security.api.dto.request.ChangePhoneNumberRequestDTO;
import one.org.security.api.dto.request.VerifyOtpRequestDTO;
import one.org.security.api.dto.response.FidoInitResponseDTO;
import one.org.security.common.model.AuthenticatedUser;
import one.org.security.core.domain.entity.User;
import one.org.security.core.service.UserService;
import one.org.security.core.service.account.UserAccountService;
import one.org.security.core.service.auth.FidoService;

@RestController
@RequestMapping("/auth")
public class AccountController {

    @Autowired
    private UserAccountService userAccountService;

    @Autowired
    private FidoService fidoService;

    @Autowired
    private UserService userService;

    private User getUser(AuthenticatedUser authenticatedUser) {
        return userService.getUserById(new ObjectId(authenticatedUser.getId()));
    }

    @PostMapping("/change-password")
    public ResponseEntity<Map<String, String>> changePassword(
            @Validated @RequestBody ChangePasswordRequestDTO request,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser) {
        User user = getUser(authenticatedUser);
        Map<String, String> response = userAccountService.changePassword(request, user);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/change-backup-email")
    public ResponseEntity<Map<String, String>> changeBackupEmail(
            @Validated @RequestBody ChangeBackupEmailRequestDTO request,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestAttribute("RAW_DEVICE_DATA") String rawDeviceData) {
        User user = getUser(authenticatedUser);
        Map<String, String> response = userAccountService.changeBackupEmail(request, user, rawDeviceData);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/change-phone-number")
    public ResponseEntity<Map<String, String>> changePhoneNumber(
            @Validated @RequestBody ChangePhoneNumberRequestDTO request,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestAttribute("RAW_DEVICE_DATA") String rawDeviceData) {
        User user = getUser(authenticatedUser);
        Map<String, String> response = userAccountService.changePhoneNumber(request, user, rawDeviceData);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/verify-backup-email")
    public ResponseEntity<Map<String, String>> verifyBackupEmail(
            @Validated @RequestBody VerifyOtpRequestDTO request,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestAttribute("RAW_DEVICE_DATA") String rawDeviceData) {
        User user = getUser(authenticatedUser);
        Map<String, String> response = userAccountService.verifyBackupEmail(request, user, rawDeviceData);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/verify-phone-number")
    public ResponseEntity<Map<String, String>> verifyPhoneNumber(
            @Validated @RequestBody VerifyOtpRequestDTO request,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestAttribute("RAW_DEVICE_DATA") String rawDeviceData) {
        User user = getUser(authenticatedUser);
        Map<String, String> response = userAccountService.verifyPhoneNumber(request, user, rawDeviceData);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/fido/register/init")
    public ResponseEntity<FidoInitResponseDTO> initFidoRegister(
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser)
            throws com.fasterxml.jackson.core.JsonProcessingException {
        User user = getUser(authenticatedUser);
        String response = fidoService.initiateRegistration(user);
        return new ResponseEntity<>(new FidoInitResponseDTO(response), HttpStatus.OK);
    }

    @PostMapping("/fido/register/complete")
    public ResponseEntity<Void> completeFidoRegister(
            @Validated @RequestBody one.org.security.api.dto.request.FidoCompleteRegisterRequestDTO request,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            @RequestAttribute("RAW_DEVICE_DATA") String rawDeviceData) {
        User user = getUser(authenticatedUser);
        fidoService.finishRegistration(user.getUsername(), request.getResponse(), rawDeviceData);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
