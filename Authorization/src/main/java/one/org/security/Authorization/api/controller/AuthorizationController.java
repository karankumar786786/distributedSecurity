package one.org.security.Authorization.api.controller;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import one.org.security.Authorization.core.domain.entity.clientEntity;
import one.org.security.Authorization.core.service.ClientService;
import one.org.security.Authorization.core.service.OAuth2Service;
import one.org.security.common.dto.TokenDTO;
import one.org.security.common.enums.TokenPurposeMessageEnum;
import one.org.security.common.service.VerifyUserService;

@RestController
@RequestMapping("/oauth2")
public class AuthorizationController {

    @Autowired
    private ClientService clientService;

    @Autowired
    private OAuth2Service oAuth2Service;

    @Autowired
    private VerifyUserService verifyUserService;

    @PostMapping("/client/register")
    public ResponseEntity<clientEntity> registerClient(
            @RequestHeader("Authorization") String token,
            @RequestHeader("RAW_DEVICE_DATA") String rawDeviceData,
            @RequestBody Map<String, String> request) {

        // Verify user token (must be logged in to register a client)
        String userToken = token.startsWith("Bearer ") ? token.substring(7) : token;
        TokenDTO userAuth = verifyUserService.verifyUser(userToken, rawDeviceData,
                TokenPurposeMessageEnum.ACCESS_TOKEN);
        if (userAuth == null) {
            return ResponseEntity.status(401).build();
        }

        String redirectUrl = request.get("redirectUrl");
        clientEntity client = clientService.registerClient(userAuth.id(), redirectUrl);
        return ResponseEntity.ok(client);
    }

    @PostMapping("/authorize")
    public ResponseEntity<Map<String, String>> authorize(
            @RequestHeader("Authorization") String token,
            @RequestHeader("RAW_DEVICE_DATA") String rawDeviceData,
            @RequestParam("client_id") String clientId,
            @RequestParam("scope") String scope) {

        // Verify user token
        String userToken = token.startsWith("Bearer ") ? token.substring(7) : token;
        TokenDTO userAuth = verifyUserService.verifyUser(userToken, rawDeviceData,
                TokenPurposeMessageEnum.ACCESS_TOKEN);
        if (userAuth == null) {
            return ResponseEntity.status(401).build();
        }

        // Generate Auth Code
        List<String> scopes = List.of(scope.split(" ")); // Space separated scopes
        String code = oAuth2Service.authorize(clientId, userAuth.id(), scopes);

        return ResponseEntity.ok(Map.of("code", code));
    }

    @PostMapping("/token")
    public ResponseEntity<Map<String, String>> token(
            @RequestParam("grant_type") String grantType,
            @RequestParam("code") String code,
            @RequestParam("client_id") String clientId,
            @RequestParam("client_secret") String clientSecret) {

        if (!"authorization_code".equals(grantType)) {
            return ResponseEntity.badRequest().body(Map.of("error", "unsupported_grant_type"));
        }

        clientEntity client = clientService.getClient(clientId);
        if (client == null) {
            return ResponseEntity.status(401).body(Map.of("error", "invalid_client"));
        }

        try {
            TokenDTO tokenDto = oAuth2Service.exchangeToken(code, clientId, clientSecret, client);
            String accessToken = oAuth2Service.generateJwt(tokenDto);
            // Refresh token logic could be similar, simplified here

            return ResponseEntity.ok(Map.of(
                    "access_token", accessToken,
                    "token_type", "Bearer",
                    "expires_in", "3600"));
        } catch (Exception e) {
            return ResponseEntity.status(400).body(Map.of("error", e.getMessage()));
        }
    }
}
