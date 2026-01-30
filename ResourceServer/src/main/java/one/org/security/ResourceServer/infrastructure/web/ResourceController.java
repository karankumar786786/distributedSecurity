package one.org.security.ResourceServer.infrastructure.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

    @GetMapping("/read")
    public String read() {
        return "You have read permission!";
    }

    @GetMapping("/write")
    public String write() {
        return "You have write permission!";
    }
}
