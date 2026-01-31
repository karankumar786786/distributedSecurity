package one.org.security.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Configuration
@ConfigurationProperties(prefix = "integrity")
@Data
public class SecurityIntegrityProperties {
    private String oldkeyId;
    private String newkeyId;
    private String oldkey;
    private String newkey;

    private String fidoOldkeyId;
    private String fidoNewkeyId;
    private String fidoOldkey;
    private String fidoNewkey;
}
