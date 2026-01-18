package one.org.security.api.controller.auth;


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

import one.org.security.api.dto.request.CheckUserExistRequestDTO;
import one.org.security.api.dto.request.LoginRequestDTO;
import one.org.security.api.dto.request.RegisterRequestDTO;
import one.org.security.api.dto.response.AuthResponseDTO;
import one.org.security.api.dto.response.CheckUserExistResponseDTO;
import one.org.security.core.service.auth.CoreAuthenticationService;
import one.org.security.core.service.auth.FidoService;
import one.org.security.api.dto.response.FidoInitResponseDTO;
import com.fasterxml.jackson.core.JsonProcessingException;
import one.org.security.api.dto.request.FidoCompleteLoginRequestDTO;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    @Autowired
    private CoreAuthenticationService authenticationService;

    @Autowired
    private FidoService fidoService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponseDTO> register(
            @Validated @RequestBody RegisterRequestDTO registerRequest,
            @RequestAttribute("RAW_DEVICE_DATA") String rawDeviceData) {
        AuthResponseDTO authResponseDTO = authenticationService.register(registerRequest, rawDeviceData);
        return new ResponseEntity<>(authResponseDTO, HttpStatus.CREATED);
    }

    @PostMapping("/check-user-exist")
    public ResponseEntity<CheckUserExistResponseDTO> checkUserExist(
            @Validated @RequestBody CheckUserExistRequestDTO checkUserExistRequestDTO,
            @RequestAttribute("RAW_DEVICE_DATA") String rawDeviceData) {
        CheckUserExistResponseDTO checkUserExistResponse = authenticationService
                .checkUserExist(checkUserExistRequestDTO, rawDeviceData);
        return new ResponseEntity<>(checkUserExistResponse, HttpStatus.OK);
    }

    @PostMapping("/login/password")
    public ResponseEntity<AuthResponseDTO> login(
            @Validated @RequestBody LoginRequestDTO loginRequestDTO,
            @Validated @RequestHeader("X-Temp-Token") String tempToken,
            @RequestAttribute("RAW_DEVICE_DATA") String rawDeviceData) {
        AuthResponseDTO authResponseDTO = authenticationService.login(loginRequestDTO, tempToken, rawDeviceData);
        return new ResponseEntity<>(authResponseDTO, HttpStatus.OK);
    }

    @PostMapping("/login/fido/init")
    public ResponseEntity<FidoInitResponseDTO> initFidoLogin(
            @Validated @RequestHeader("X-Temp-Token") String tempToken,
            @RequestAttribute("RAW_DEVICE_DATA") String rawDeviceData
        )
            throws JsonProcessingException {
        String response = fidoService.initiateLogin(tempToken,rawDeviceData);
        return ResponseEntity.ok(new FidoInitResponseDTO(response));
    }

    @PostMapping("/login/fido/complete")
    public ResponseEntity<AuthResponseDTO> completeFidoLogin(
            @Validated @RequestHeader("X-Temp-Token") String tempToken,
            @RequestAttribute("RAW_DEVICE_DATA") String rawDeviceData,
            @RequestBody FidoCompleteLoginRequestDTO request) {
        AuthResponseDTO response = fidoService.finishLogin(tempToken, rawDeviceData, request);
        return ResponseEntity.ok(response);
    }
}
