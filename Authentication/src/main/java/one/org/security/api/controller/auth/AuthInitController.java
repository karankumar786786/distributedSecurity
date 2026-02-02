package one.org.security.api.controller.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;

import one.org.security.api.Errors.CustomExceptions.InvalidSessionException;
import one.org.security.api.dto.enums.CheckUserExistRequestAvailableEnum;
import one.org.security.api.dto.request.FidoCompleteLoginRequestDTO;
import one.org.security.api.dto.request.LoginRequestDTO;
import one.org.security.api.dto.response.FidoInitResponseDTO;
import one.org.security.api.dto.response.InitTokenResponseDTO;
import one.org.security.api.dto.response.LoginSuccessResponseDTO;
import one.org.security.api.dto.response.TokenResponseDTO;
import one.org.security.core.service.auth.CoreAuthenticationService;
import one.org.security.core.service.auth.FidoService;
import one.org.security.core.service.auth.InitSessionService;
import one.org.security.core.service.auth.InitSessionService.InitTokenData;

@RestController
@RequestMapping("/init")
public class AuthInitController {

        @Autowired
        private CoreAuthenticationService authenticationService;

        @Autowired
        private FidoService fidoService;

        @Autowired
        private InitSessionService initSessionService;

        /**
         * Initialize password login flow.
         * Returns an init token instead of setting cookies.
         */
        @PostMapping("/login/password")
        public ResponseEntity<InitTokenResponseDTO> initPasswordLogin(
                        @RequestAttribute("USERNAME") String username,
                        @RequestAttribute("USER-ID") String userId,
                        @RequestAttribute("INIT-SESSION") String sessionData) {

                String initToken = initSessionService.generateInitToken(
                                userId,
                                username,
                                "LOGIN-PASSWORD-SESSION",
                                sessionData);

                return ResponseEntity.ok()
                                .header("X-Init-Token", initToken)
                                .body(new InitTokenResponseDTO(initToken, "PASSWORD"));
        }

        /**
         * Complete password login flow.
         * Expects init token in X-Init-Token header.
         */
        @PostMapping("/login/password/complete")
        public ResponseEntity<TokenResponseDTO> completePasswordLogin(
                        @Validated @RequestBody LoginRequestDTO loginRequestDTO,
                        @RequestHeader(value = "X-Init-Token", required = true) String initToken,
                        @RequestAttribute("IP-ADDRESS") String ipAddress,
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {

                // Validate init token
                InitTokenData tokenData = initSessionService.validateInitToken(initToken);
                if (tokenData == null) {
                        throw new InvalidSessionException("Invalid or expired init token");
                }

                if (!"LOGIN-PASSWORD-SESSION".equals(tokenData.flowType())) {
                        throw new InvalidSessionException("Invalid session type for password login");
                }

                LoginSuccessResponseDTO loginResponse = authenticationService
                                .completePasswordLogin(loginRequestDTO, tokenData.username(), ipAddress, rawDeviceBind);

                // Return JWT token in response body and header (no cookies)
                TokenResponseDTO tokenResponse = new TokenResponseDTO(
                                loginResponse.getToken(),
                                loginResponse.getUserId(),
                                loginResponse.getUsername(),
                                null);

                return ResponseEntity.ok()
                                .header("X-Auth-Token", loginResponse.getToken())
                                .body(tokenResponse);
        }

        /**
         * Initialize FIDO login flow.
         * Returns an init token instead of setting cookies.
         */
        @PostMapping("/login/fido")
        public ResponseEntity<FidoInitResponseDTO> initFidoLogin(
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceData,
                        @RequestAttribute("USERNAME") String username,
                        @RequestAttribute("USER-ID") String userId,
                        @RequestAttribute("INIT-SESSION") String sessionData)
                        throws JsonProcessingException {

                String[] sessionDataArray = sessionData.split("\\|");
                String reason = sessionDataArray[2];
                if (!CheckUserExistRequestAvailableEnum.LOGIN.toString().equals(reason)) {
                        throw new InvalidSessionException("invalid session");
                }

                String initToken = initSessionService.generateInitToken(
                                userId,
                                username,
                                "LOGIN-FIDO-SESSION",
                                sessionData);

                String fidoOptions = fidoService.initiateLogin(username);

                return ResponseEntity.ok()
                                .header("X-Init-Token", initToken)
                                .body(new FidoInitResponseDTO(fidoOptions, initToken));
        }

        /**
         * Complete FIDO login flow.
         * Expects init token in X-Init-Token header.
         */
        @PostMapping("/login/fido/complete")
        public ResponseEntity<TokenResponseDTO> completeFidoLogin(
                        @Validated @RequestBody FidoCompleteLoginRequestDTO request,
                        @RequestHeader(value = "X-Init-Token", required = true) String initToken,
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind,
                        @RequestAttribute("IP-ADDRESS") String ipAddress) {

                // Validate init token
                InitTokenData tokenData = initSessionService.validateInitToken(initToken);
                if (tokenData == null) {
                        throw new InvalidSessionException("Invalid or expired init token");
                }

                if (!"LOGIN-FIDO-SESSION".equals(tokenData.flowType())) {
                        throw new InvalidSessionException("Invalid session type for FIDO login");
                }

                LoginSuccessResponseDTO loginResponse = fidoService
                                .finishLogin(ipAddress, rawDeviceBind, request, tokenData.username());

                // Return JWT token in response body and header (no cookies)
                TokenResponseDTO tokenResponse = new TokenResponseDTO(
                                loginResponse.getToken(),
                                loginResponse.getUserId(),
                                loginResponse.getUsername(),
                                null);

                return ResponseEntity.ok()
                                .header("X-Auth-Token", loginResponse.getToken())
                                .body(tokenResponse);
        }
}
