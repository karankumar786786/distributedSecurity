package one.org.security.Autherization.api.controller.key;

import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import one.org.security.Autherization.api.dto.request.SecurityIntegrityKeyCreateRequest;
import one.org.security.Autherization.api.dto.response.SecurityIntegrityKeyCreateResponse;
import one.org.security.Autherization.core.domain.entity.ClientHmacEntity;
import one.org.security.Autherization.core.service.Encoding.HmacEncodingService;
import one.org.security.Autherization.infrastructure.persistance.ClientHmacRepository;

@RestController
@RequestMapping("/key")
public class KeyController {

    @Autowired
    private ClientHmacRepository clientHmacRepository;

    @Autowired
    private HmacEncodingService hmacEncodingService;

    @PostMapping("/client/create")
    public ResponseEntity<SecurityIntegrityKeyCreateResponse> createClientKey(
            @Validated @RequestBody SecurityIntegrityKeyCreateRequest request) {
        ClientHmacEntity keyEntity = hmacEncodingService.createKey(request.key());
        return new ResponseEntity<>(
                new SecurityIntegrityKeyCreateResponse(keyEntity.getId().toHexString(), request.key()),
                HttpStatus.CREATED);
    }

    @DeleteMapping("/client/{id}")
    public ResponseEntity<Void> deleteClientKey(@PathVariable String id) {
        clientHmacRepository.deleteById(new ObjectId(id));
        return new ResponseEntity<>(HttpStatus.ACCEPTED);
    }
}
