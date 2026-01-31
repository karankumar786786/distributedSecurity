package one.org.security.core.domain.entity;

import lombok.Data;

@Data
public class SecurityIntegrity {
    private String hashedPassword;
    private String integrityHmacKeyId;
    private String integrityHmac;
}
