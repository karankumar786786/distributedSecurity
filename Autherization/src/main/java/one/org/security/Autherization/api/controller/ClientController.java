package one.org.security.Autherization.api.controller;

import java.util.Arrays;
import java.util.List;

import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import one.org.security.Autherization.api.dto.request.CreateClientRequestDTO;
import one.org.security.Autherization.api.dto.request.UpdateClientRedirectUrlRequestDTO;
import one.org.security.Autherization.api.dto.response.CreateClientResponseDTO;
import one.org.security.Autherization.api.dto.response.GetClientListResponseDTO;
import one.org.security.Autherization.core.domain.entity.ClientEntity;
import one.org.security.Autherization.core.domain.entity.UserMockEntity;
import one.org.security.Autherization.core.service.Client.ClientService;
import one.org.security.Autherization.core.service.Encoding.CustomEncodingService;

@RestController
@RequestMapping("/client")
public class ClientController {

    @Autowired
    private ClientService clientService;

    @Autowired
    private CustomEncodingService customEncodingService;

    @Autowired
    private Environment environment;

    @PostMapping("/create-client")
    public ResponseEntity<CreateClientResponseDTO> createClient(
            @RequestBody @Validated CreateClientRequestDTO request,
            @AuthenticationPrincipal UserMockEntity user) {

        validateRedirectUrl(request.redirectUrl());

        // Cryptographically secure random secret generation (32 bytes = 256 bits)
        java.security.SecureRandom secureRandom = new java.security.SecureRandom();
        byte[] secretBytes = new byte[32];
        secureRandom.nextBytes(secretBytes);
        String clientSecret = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(secretBytes);
        ClientEntity client = ClientEntity.builder()
                .clientId(request.clientId())
                .hashedClientSecretHmac(customEncodingService.encode(clientSecret))
                .userId(user.getId())
                .redirectUrl(request.redirectUrl())
                .writeAllowed(request.write())
                .allowPersonalData(request.personalDataAccess())
                .allowProfile(request.profile())
                .writeAllowed(request.write())
                .showConsentForm(true)
                .build();
        clientService.saveClient(client);
        CreateClientResponseDTO response = new CreateClientResponseDTO(client.getClientId(), clientSecret);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @PatchMapping("/update-client-redirect-url")
    public ResponseEntity<Void> updateClientRedirectUrl(
            @AuthenticationPrincipal UserMockEntity user,
            @Validated @RequestBody UpdateClientRedirectUrlRequestDTO request) {

        validateRedirectUrl(request.redirectUrl());

        // if client will not found then it will throw client not found exception in the
        // service already
        ClientEntity client = clientService.findByClientId(request.clientId());

        // Ensure user owns the client
        if (!client.getUserId().equals(user.getId())) {
            // Or throw a specific forbidden/not found exception
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "User not authorized to update this client");
        }

        client.setRedirectUrl(request.redirectUrl());
        clientService.saveClient(client);
        return new ResponseEntity<>(HttpStatus.ACCEPTED);
    }

    @GetMapping("/list-client")
    public ResponseEntity<GetClientListResponseDTO> getClientList(
            @AuthenticationPrincipal UserMockEntity user) {
        List<ClientEntity> clients = clientService.findByUserId(user.getId());
        List<String> clientIds = clients.stream()
                .map(ClientEntity::getClientId)
                .collect(Collectors.toList());
        return new ResponseEntity<>(new GetClientListResponseDTO(clientIds), HttpStatus.OK);
    }

    @DeleteMapping("/delete/{clientId}")
    public ResponseEntity<Void> deleteClient(
            @PathVariable String clientId,
            @AuthenticationPrincipal UserMockEntity user) {
        ClientEntity client = clientService.findByClientId(clientId);
        // Ensure user owns the client
        if (!client.getUserId().equals(user.getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "User not authorized to delete this client");
        }
        clientService.deleteClient(clientId);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    private void validateRedirectUrl(String url) {
        if (url.startsWith("http://localhost")) {
            boolean isDev = Arrays.asList(environment.getActiveProfiles()).contains("dev");
            if (!isDev) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "http://localhost redirect URIs are only allowed in 'dev' profile.");
            }
        }
    }
}
