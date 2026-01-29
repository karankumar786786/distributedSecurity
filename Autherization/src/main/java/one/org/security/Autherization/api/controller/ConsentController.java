package one.org.security.Autherization.api.controller;

import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ConsentController {

    @GetMapping("/oauth2/consent")
    public String consent(Principal principal, Model model,
            @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
            @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
            @RequestParam(OAuth2ParameterNames.STATE) String state) {

        System.out.println("DEBUG: ConsentController - Received Request");
        System.out.println("DEBUG: clientId: " + clientId);
        System.out.println("DEBUG: scope: " + scope);
        System.out.println("DEBUG: state: " + state);

        Set<String> scopesToApprove = new HashSet<>();
        if (StringUtils.hasText(scope)) {
            Collections.addAll(scopesToApprove, scope.split(" "));
        }

        model.addAttribute("clientId", clientId);
        model.addAttribute("state", state);
        model.addAttribute("scopes", scopesToApprove);
        model.addAttribute("principalName", principal.getName());
        model.addAttribute("redirectUri", ""); // Can be extracted if needed

        return "consent";
    }
}
