package one.org.security.Authorization.api.controller;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import one.org.security.Authorization.core.domain.entity.clientEntity;
import one.org.security.Authorization.core.service.ClientService;
import one.org.security.Authorization.core.service.OAuth2Service;
import one.org.security.common.model.AuthenticatedUser;
import one.org.security.common.dto.TokenDTO;

@RestController
@RequestMapping("/oauth2")
public class AuthorizationController {

    @Autowired
    private ClientService clientService;

    @Autowired
    private OAuth2Service oAuth2Service;

    @PostMapping("/client/register")
    public ResponseEntity<clientEntity> registerClient(
            @org.springframework.security.core.annotation.AuthenticationPrincipal AuthenticatedUser user,
            @RequestBody Map<String, String> request) {

        if (user == null) {
            return ResponseEntity.status(401).build();
        }

        String redirectUrl = request.get("redirectUrl");
        clientEntity client = clientService.registerClient(user.getId(), redirectUrl);
        return ResponseEntity.ok(client);
    }

    @PostMapping("/authorize")
    public ResponseEntity<Map<String, String>> authorize(
            @org.springframework.security.core.annotation.AuthenticationPrincipal AuthenticatedUser user,
            @RequestParam("client_id") String clientId,
            @RequestParam("scope") String scope) {

        if (user == null) {
            return ResponseEntity.status(401).build();
        }

        // Generate Auth Code
        List<String> scopes = List.of(scope.split(" ")); // Space separated scopes
        String code = oAuth2Service.authorize(clientId, user.getId(), scopes);

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
