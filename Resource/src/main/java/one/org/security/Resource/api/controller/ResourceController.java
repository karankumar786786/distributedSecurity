package one.org.security.Resource.api.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import one.org.security.Resource.core.domain.entity.ResourceEntity;
import one.org.security.common.model.AuthenticatedUser;

@RestController
@RequestMapping("/resource")
public class ResourceController {

    @GetMapping
    public ResponseEntity<ResourceEntity> getResource(
            @org.springframework.security.core.annotation.AuthenticationPrincipal AuthenticatedUser user) {
                System.out.println(user);
        if (user == null) {
            return ResponseEntity.status(401).build();
        }

        if (user.getScopes() == null || !user.getScopes().contains("read")) {
            return ResponseEntity.status(403).build();
        }

        // Return dummy resource for demo
        return ResponseEntity.ok(ResourceEntity.builder()
                .name("Demo Resource")
                .dob("01-01-2000")
                .build());
    }
}
