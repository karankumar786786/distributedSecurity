package one.org.security.api.controller.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
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
import one.org.security.core.service.auth.InitSessionService;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

        @Autowired
        private CoreAuthenticationService authenticationService;

        @Autowired
        private InitSessionService initSessionService;

        @PostMapping("/register")
        public ResponseEntity<Void> register(
                        @Validated @RequestBody RegisterRequestDTO registerRequest,
                        @RequestAttribute(name = "IP-ADDRESS") String ipAddress,
                        @RequestAttribute(name = "RAW-DEVICE-BIND") String rawDeviceBind) {
                authenticationService.register(registerRequest, rawDeviceBind, ipAddress);
                return new ResponseEntity<>(HttpStatus.CREATED);
        }

        /**
         * Check if user exists and return init token for login flow.
         * Returns init token in response body instead of setting cookies.
         */
        @PostMapping("/check-user-exist")
        public ResponseEntity<CheckUserExistClientResponseDTO> checkUserExist(
                        @Validated @RequestBody CheckUserExistRequestDTO request,
                        @RequestAttribute("IP-ADDRESS") String ipAddress,
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {
                CheckUserExistResponseDTO checkUserExistResponse = authenticationService.checkUserExist(request,
                                rawDeviceBind,
                                ipAddress);

                // Build session data (same format as before, for compatibility)
                String sessionData = checkUserExistResponse.initSession().signature() + "|"
                                + checkUserExistResponse.initSession().keyId() + "|" + request.reason().name() + "|"
                                + checkUserExistResponse.userId() + "|" + checkUserExistResponse.username();

                // Generate init token instead of cookie
                String initToken = initSessionService.generateInitToken(
                                checkUserExistResponse.userId(),
                                checkUserExistResponse.username(),
                                "INIT", // This is just the initial check, flow type will be set in next step
                                sessionData);

                CheckUserExistClientResponseDTO response = new CheckUserExistClientResponseDTO(
                                checkUserExistResponse.exist(),
                                checkUserExistResponse.data(),
                                initToken);

                return ResponseEntity.status(HttpStatus.OK)
                                .header("X-Init-Token", initToken)
                                .body(response);
        }
}
