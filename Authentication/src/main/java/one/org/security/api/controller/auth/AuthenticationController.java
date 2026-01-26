package one.org.security.api.controller.auth;

import org.springframework.http.HttpHeaders;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import one.org.security.api.dto.request.CheckUserExistRequestDTO;
import one.org.security.api.dto.request.RegisterRequestDTO;
import one.org.security.api.dto.response.CheckUserExistClientResponseDTO;
import one.org.security.api.dto.response.CheckUserExistResponseDTO;
import one.org.security.core.service.auth.CoreAuthenticationService;
@RestController
@RequestMapping("/auth")
public class AuthenticationController {

        @Autowired
        private CoreAuthenticationService authenticationService;

        @PostMapping("/register")
        public ResponseEntity<Void> register(
                        @Validated @RequestBody RegisterRequestDTO registerRequest,
                        @RequestAttribute(name = "IP-ADDRESS") String ipAddress,
                        @RequestAttribute(name = "RAW-DEVICE-BIND") String rawDeviceBind
                ) {
                authenticationService.register(registerRequest, rawDeviceBind, ipAddress);
                return new ResponseEntity<>(HttpStatus.CREATED);
        }

        @PostMapping("/check-user-exist")
        public ResponseEntity<CheckUserExistClientResponseDTO> checkUserExist(
                        @Validated @RequestBody CheckUserExistRequestDTO request,
                        @RequestAttribute("IP-ADDRESS") String ipAddress,
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind
                ) {
                CheckUserExistResponseDTO checkUserExistResponse = authenticationService.checkUserExist(request, rawDeviceBind,
                                ipAddress);
                String cookieData = checkUserExistResponse.initSession().signature() + "|" + checkUserExistResponse.initSession().keyId() + "|" + request.reason() + "|"
                                + checkUserExistResponse.userId()+checkUserExistResponse.username();
                ResponseCookie cookie = ResponseCookie.from("INIT-SESSION", cookieData)
                                .httpOnly(true)
                                .secure(false) // true only for https
                                // .domain("localhost")
                                .path("/")
                                .sameSite("Lax")
                                .maxAge(300L)
                                .build();
                        CheckUserExistClientResponseDTO response = new CheckUserExistClientResponseDTO(checkUserExistResponse.exist(), checkUserExistResponse.data());
                return ResponseEntity.status(HttpStatus.OK).header(HttpHeaders.SET_COOKIE, cookie.toString())
                                .body(response);
        }
}
