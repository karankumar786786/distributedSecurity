package one.org.security.Autherization.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Data
@Configuration
@ConfigurationProperties(prefix = "oauth2.keys")
public class KeyProperties {
    private KeyInfo current;
    private KeyInfo old;

    @Data
    public static class KeyInfo {
        private String keyId;
        private String privateKey;
    }
}
