package one.org.security.api.controller.recovery;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import one.org.security.api.dto.request.ForgetPasswordRequestDTO;
import one.org.security.api.dto.request.VerifyForgetPasswordRequestDTO;
import one.org.security.core.service.recovery.PasswordRecoveryService;

@RestController
@RequestMapping("/auth")
public class RecoveryController {

    @Autowired
    private PasswordRecoveryService passwordRecoveryService;

    @PostMapping("/forget-password")
    public ResponseEntity<Map<String, String>> forgetPassword(
            @Validated @RequestBody ForgetPasswordRequestDTO forgetPasswordRequestDTO,
            @Validated @RequestHeader("X-Temp-Token") String tempToken,
            @RequestAttribute("RAW_DEVICE_DATA") String rawDeviceData) {
        Map<String, String> response = passwordRecoveryService.forgetPassword(forgetPasswordRequestDTO, tempToken,
                rawDeviceData);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/verify-forget-password")
    public ResponseEntity<Map<String, String>> verifyForgetPassword(
            @Validated @RequestBody VerifyForgetPasswordRequestDTO verifyForgetRequest,
            @Validated @RequestHeader("X-Forget-Password-Token") String token,
            @RequestAttribute("RAW_DEVICE_DATA") String rawDeviceData) {

        Map<String, String> response = passwordRecoveryService.verifyForgetPassword(verifyForgetRequest, token,
                rawDeviceData);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
