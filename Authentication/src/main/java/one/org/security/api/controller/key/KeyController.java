package one.org.security.api.controller.key;

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

import one.org.security.api.dto.request.SecurityIntegrityKeyCreateRequest;
import one.org.security.api.dto.response.SecurityIntegrityKeyCreateResponse;
import one.org.security.core.domain.entity.SecurityIntegrityFidoKeyEntity;
import one.org.security.core.domain.entity.SecurityIntegrityKeyEntity;
import one.org.security.infrastructure.persistence.SecurityIntegrityFidoKeyRepository;
import one.org.security.infrastructure.persistence.SecurityIntegrityKeyRepository;
import one.org.security.core.service.Security.SecurityIntegrityService;

@RestController
@RequestMapping("/key")
public class KeyController {

    @Autowired
    private SecurityIntegrityKeyRepository securityIntegrityKeyRepository;

    @Autowired
    private SecurityIntegrityFidoKeyRepository securityIntegrityFidoKeyRepository;

    @Autowired
    private SecurityIntegrityService securityIntegrityService;

    @PostMapping("/integrity/create")
    public ResponseEntity<SecurityIntegrityKeyCreateResponse> createIntegrityKey(
            @Validated @RequestBody SecurityIntegrityKeyCreateRequest request) {
        SecurityIntegrityKeyEntity save = securityIntegrityService.createKey(request.key());
        return new ResponseEntity<>(new SecurityIntegrityKeyCreateResponse(save.getId().toHexString(), request.key()),
                HttpStatus.CREATED);
    }

    @DeleteMapping("/integrity/{id}")
    public ResponseEntity<Void> deleteIntegrityKey(@PathVariable String id) {
        securityIntegrityKeyRepository.deleteById(new ObjectId(id));
        return new ResponseEntity<>(HttpStatus.ACCEPTED);
    }

    @PostMapping("/fido/create")
    public ResponseEntity<SecurityIntegrityKeyCreateResponse> createFidoKey(
            @Validated @RequestBody SecurityIntegrityKeyCreateRequest request) {
        SecurityIntegrityFidoKeyEntity keyEntity = SecurityIntegrityFidoKeyEntity.builder().key(request.key()).build();
        SecurityIntegrityFidoKeyEntity save = securityIntegrityFidoKeyRepository.save(keyEntity);
        return new ResponseEntity<>(new SecurityIntegrityKeyCreateResponse(save.getId().toHexString(), save.getKey()),
                HttpStatus.CREATED);
    }

    @DeleteMapping("/fido/{id}")
    public ResponseEntity<Void> deleteFidoKey(@PathVariable String id) {
        securityIntegrityFidoKeyRepository.deleteById(new ObjectId(id));
        return new ResponseEntity<>(HttpStatus.ACCEPTED);
    }
}
