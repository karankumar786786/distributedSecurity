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
    public ResponseEntity<one.org.security.Authorization.api.dto.ClientRegistrationResponseDTO> registerClient(
            @org.springframework.security.core.annotation.AuthenticationPrincipal AuthenticatedUser user,
            @jakarta.validation.Valid @RequestBody one.org.security.Authorization.api.dto.ClientRegistrationRequestDTO request)
            throws Exception {
        System.out.println("here");

        if (user == null) {
            return ResponseEntity.status(401).build();
        }

        if (request.getRedirectUrl() == null) {
            throw new Exception("redirectUrl is required");
        }
        one.org.security.Authorization.api.dto.ClientRegistrationResponseDTO client = clientService
                .registerClient(user.getId(), request);
        return ResponseEntity.ok(client);
    }

    @PostMapping("/authorize")
    public ResponseEntity<one.org.security.Authorization.api.dto.AuthorizeResponseDTO> authorize(
            @org.springframework.security.core.annotation.AuthenticationPrincipal AuthenticatedUser user,
            @jakarta.validation.Valid @RequestBody one.org.security.Authorization.api.dto.AuthorizeRequestDTO request) {
        System.out.println("Authorize request received: " + request);

        if (user == null) {
            return ResponseEntity.status(401).build();
        }

        // Generate Auth Code
        List<String> scopes = List.of(request.getScope().split(" ")); // Space separated scopes
        String code = oAuth2Service.authorize(request.getClientId(), user.getId(), scopes);

        return ResponseEntity.ok(one.org.security.Authorization.api.dto.AuthorizeResponseDTO.builder()
                .code(code)
                .build());
    }

    @PostMapping("/token")
    public ResponseEntity<one.org.security.Authorization.api.dto.TokenResponseDTO> token(
            @jakarta.validation.Valid @RequestBody one.org.security.Authorization.api.dto.TokenRequestDTO request) {

        if (!"authorization_code".equals(request.getGrantType())) {
            return ResponseEntity.badRequest().body(one.org.security.Authorization.api.dto.TokenResponseDTO.builder()
                    .error("unsupported_grant_type")
                    .build());
        }

        clientEntity client = clientService.getClient(request.getClientId());
        if (client == null) {
            return ResponseEntity.status(401).body(one.org.security.Authorization.api.dto.TokenResponseDTO.builder()
                    .error("invalid_client")
                    .build());
        }

        try {
            TokenDTO tokenDto = oAuth2Service.exchangeToken(request.getCode(), request.getClientId(),
                    request.getClientSecret(), client);
            String accessToken = oAuth2Service.generateJwt(tokenDto);
            // Refresh token logic could be similar, simplified here

            return ResponseEntity.ok(one.org.security.Authorization.api.dto.TokenResponseDTO.builder()
                    .accessToken(accessToken)
                    .tokenType("Bearer")
                    .expiresIn("3600")
                    .build());
        } catch (Exception e) {
            return ResponseEntity.status(400).body(one.org.security.Authorization.api.dto.TokenResponseDTO.builder()
                    .error(e.getMessage())
                    .build());
        }
    }
}
