package one.org.security.api.controller.otp;

import java.util.Collections;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import one.org.security.api.dto.request.ResendOtpRequestDTO;
import one.org.security.core.service.otp.OtpService;

@RestController
@RequestMapping("/auth")
public class OtpController {

    @Autowired
    private OtpService otpService;

    @PostMapping("/resend-otp")
    public ResponseEntity<Map<String, String>> resendOtp(
            @RequestHeader("X-Temp-Token") String tempToken,
            @RequestAttribute("RAW_DEVICE_DATA") String rawDeviceData,
            @RequestBody ResendOtpRequestDTO request
        ) {
        otpService.resendOtp(request,tempToken, rawDeviceData);
        return new ResponseEntity<>(Collections.singletonMap("message", "OTP resent successfully"), HttpStatus.OK);
    }
}
