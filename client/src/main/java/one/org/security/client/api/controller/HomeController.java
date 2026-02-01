package one.org.security.client.api.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
public class HomeController {

    @GetMapping("/")
    public Map<String, Object> home(@AuthenticationPrincipal OAuth2User principal, HttpServletRequest request) {
        if (principal != null) {
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Welcome! You are logged in.");
            response.put("user", principal.getAttributes());
            response.put("name", principal.getAttribute("name"));
            response.put("email", principal.getAttribute("email"));
            return response;
        }
        return Collections.singletonMap("message", "Not logged in. Visit /oauth2/authorization/testclient1 to login.");
    }

    @GetMapping("/login")
    public Map<String, Object> login() {
        return Collections.singletonMap("message", "Redirecting to OAuth2 login...");
    }

    @GetMapping("/user")
    public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal) {
        if (principal != null) {
            return principal.getAttributes();
        }
        return Collections.singletonMap("error", "Not authenticated");
    }
}
