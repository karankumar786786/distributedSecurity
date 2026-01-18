package one.org.security.Resource.api.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import one.org.security.Resource.core.domain.entity.ResourceEntity;
import one.org.security.common.dto.TokenDTO;
import one.org.security.common.enums.TokenPurposeMessageEnum;
import one.org.security.common.service.VerifyUserService;

@RestController
@RequestMapping("/resource")
public class ResourceController {

    @Autowired
    private VerifyUserService verifyUserService;

    @GetMapping
    public ResponseEntity<ResourceEntity> getResource(
            @RequestHeader("Authorization") String token,
            @RequestHeader("RAW_DEVICE_DATA") String rawDeviceData) {

        String accessToken = token.startsWith("Bearer ") ? token.substring(7) : token;
        TokenDTO tokenData = verifyUserService.verifyUser(accessToken, rawDeviceData,
                TokenPurposeMessageEnum.ACCESS_TOKEN);

        if (tokenData == null) {
            return ResponseEntity.status(401).build();
        }

        if (tokenData.scope() == null || !tokenData.scope().contains("read")) {
            return ResponseEntity.status(403).build();
        }

        // Return dummy resource for demo
        return ResponseEntity.ok(ResourceEntity.builder()
                .name("Demo Resource")
                .dob("01-01-2000")
                .build());
    }
}
