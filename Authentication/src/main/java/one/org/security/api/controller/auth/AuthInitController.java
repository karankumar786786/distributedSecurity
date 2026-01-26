package one.org.security.api.controller.auth;

import org.springframework.http.HttpHeaders;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;

import one.org.security.api.Errors.CustomExceptions.InvalidSessionException;
import one.org.security.api.dto.enums.CheckUserExistRequestAvailableEnum;
import one.org.security.api.dto.request.FidoCompleteLoginRequestDTO;
import one.org.security.api.dto.request.LoginRequestDTO;
import one.org.security.api.dto.response.FidoInitResponseDTO;
import one.org.security.api.dto.response.LoginSuccessResponseDTO;
import one.org.security.core.service.auth.CoreAuthenticationService;
import one.org.security.core.service.auth.FidoService;


@RestController
@RequestMapping("/init")
public class AuthInitController {

        @Autowired
        private CoreAuthenticationService authenticationService;

        @Autowired
        private FidoService fidoService;

        @PostMapping("/login/password")
        public ResponseEntity<Void> initPasswordLogin(
                        @RequestAttribute("USERNAME") String username,
                        @RequestAttribute("INIT-SESSION") String sessionData) {
                ResponseCookie initSessionCookie = ResponseCookie.from("INIT-SESSION", sessionData)
                                .httpOnly(true)
                                .secure(false)
                                .path("/")
                                .sameSite("Lax")
                                .maxAge(300L)
                                .build();
                ResponseCookie loginPasswordCookie = ResponseCookie.from("LOGIN-SESSION", "LOGIN-PASSWORD-SESSION")
                                .httpOnly(true)
                                .secure(false)
                                .path("/")
                                .sameSite("Lax")
                                .maxAge(300L)
                                .build();
                // 3. Attach both to the response headers
                return ResponseEntity.ok()
                                .header(HttpHeaders.SET_COOKIE, initSessionCookie.toString())
                                .header(HttpHeaders.SET_COOKIE, loginPasswordCookie.toString())
                                .build();
        }

        @PostMapping("/login/password/complete")
        public ResponseEntity<Void> completePasswordLogin(
                        @Validated @RequestBody LoginRequestDTO loginRequestDTO,
                        @RequestAttribute("USERNAME") String username,
                        // here init session is not required because username is extreacted from filture
                        // and device hash will be regenerated now
                        @RequestAttribute("LOGIN-SESSION") String loginSession,
                        @RequestAttribute("IP-ADDRESS") String ipAddress,
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind) {
                if (!"LOGIN-PASSWORD-SESSION".equals(loginSession)) {
                        throw new InvalidSessionException("invalid session");
                }
                LoginSuccessResponseDTO loginResponse = authenticationService
                                .completePasswordLogin(loginRequestDTO, username, ipAddress, rawDeviceBind);
                String sessionData = loginResponse.getUserId() + loginResponse.getUsername() + loginResponse.getHash() + loginResponse.getHashKeyId();

                ResponseCookie sessionCookie = ResponseCookie.from("SESSION", sessionData)
                                .httpOnly(true)
                                .secure(false)
                                .path("/")
                                .sameSite("Lax")
                                .maxAge(60 * 60 * 24) // 1 day
                                .build();

                ResponseCookie clearInitCookie = ResponseCookie.from("INIT-SESSION", "")
                                .httpOnly(true)
                                .secure(false)
                                .path("/")
                                .maxAge(0)
                                .build();

                ResponseCookie clearLoginCookie = ResponseCookie.from("LOGIN-SESSION", "")
                                .httpOnly(true)
                                .secure(false)
                                .path("/")
                                .maxAge(0)
                                .build();

                return ResponseEntity.ok()
                                .header(HttpHeaders.SET_COOKIE, sessionCookie.toString())
                                .header(HttpHeaders.SET_COOKIE, clearInitCookie.toString())
                                .header(HttpHeaders.SET_COOKIE, clearLoginCookie.toString())
                                .build();
        }

        @PostMapping("/login/fido")
        public ResponseEntity<FidoInitResponseDTO> initFidoLogin(
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceData,
                        @RequestAttribute("USERNAME") String username,
                        @RequestAttribute("INIT-SESSION") String sessionData)
                        throws JsonProcessingException {
                String[] sessionDataArray = sessionData.split("\\|");
                String reason = sessionDataArray[2];
                if (!CheckUserExistRequestAvailableEnum.LOGIN.toString().equals(reason)) {
                        throw new InvalidSessionException("invalid session");
                }
                ;
                ResponseCookie initSessionCookie = ResponseCookie.from("INIT-SESSION", sessionData)
                                .httpOnly(true)
                                .secure(false)
                                .path("/")
                                .sameSite("Lax")
                                .maxAge(300L)
                                .build();
                ResponseCookie loginPasswordCookie = ResponseCookie.from("LOGIN-SESSION", "LOGIN-FIDO-SESSION")
                                .httpOnly(true)
                                .secure(false)
                                .path("/")
                                .sameSite("Lax")
                                .maxAge(300L)
                                .build();
                // Assuming fidoService is also updated to use session
                String response = fidoService.initiateLogin(username);
                return ResponseEntity.ok()
                                .header(HttpHeaders.SET_COOKIE, initSessionCookie.toString())
                                .header(HttpHeaders.SET_COOKIE, loginPasswordCookie.toString())
                                .body(new FidoInitResponseDTO(response));
        }

        @PostMapping("/login/fido/complete")
        public ResponseEntity<Void> completeFidoLogin(
                        @Validated @RequestBody FidoCompleteLoginRequestDTO request,
                        @RequestAttribute("RAW-DEVICE-BIND") String rawDeviceBind,
                        @RequestAttribute("INIT-SESSION") String initSessionData,
                        @RequestAttribute("LOGIN-SESSION") String loginSession,
                        @RequestAttribute("IP-ADDRESS") String ipAddress,
                        @RequestAttribute("USERNAME") String username
                ) {

                if (!"LOGIN-FIDO-SESSION".equals(loginSession)) {
                        throw new InvalidSessionException("invalid session");
                }

                LoginSuccessResponseDTO loginResponse = fidoService
                                .finishLogin(ipAddress, rawDeviceBind, request, username);

                String sessionData = loginResponse.getUserId()+loginResponse.getUsername()+loginResponse.getHash()+loginResponse.getHashKeyId();

                ResponseCookie sessionCookie = ResponseCookie.from("SESSION", sessionData)
                                .httpOnly(true)
                                .secure(false)
                                .path("/")
                                .sameSite("Lax")
                                .maxAge(60 * 60 * 24) // 1 day
                                .build();

                ResponseCookie clearInitCookie = ResponseCookie.from("INIT-SESSION", "")
                                .httpOnly(true)
                                .secure(false)
                                .path("/")
                                .maxAge(0)
                                .build();

                ResponseCookie clearLoginCookie = ResponseCookie.from("LOGIN-SESSION", "")
                                .httpOnly(true)
                                .secure(false)
                                .path("/")
                                .maxAge(0)
                                .build();

                return ResponseEntity.ok()
                                .header(HttpHeaders.SET_COOKIE, sessionCookie.toString())
                                .header(HttpHeaders.SET_COOKIE, clearInitCookie.toString())
                                .header(HttpHeaders.SET_COOKIE, clearLoginCookie.toString())
                                .build();
        }
}
