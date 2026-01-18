package one.org.security.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private KeyConfig access;
    private KeyConfig refresh;
    private KeyConfig temp;
    private String issuer;
    private int accessExpiration;
    private int refreshExpiration;
    private int tempExpiration;
    private int recoveryExpiration;

    public KeyConfig getAccess() {
        return access;
    }

    public void setAccess(KeyConfig access) {
        this.access = access;
    }

    public KeyConfig getRefresh() {
        return refresh;
    }

    public void setRefresh(KeyConfig refresh) {
        this.refresh = refresh;
    }

    public KeyConfig getTemp() {
        return temp;
    }

    public void setTemp(KeyConfig temp) {
        this.temp = temp;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public int getAccessExpiration() {
        return accessExpiration;
    }

    public void setAccessExpiration(int accessExpiration) {
        this.accessExpiration = accessExpiration;
    }

    public int getRefreshExpiration() {
        return refreshExpiration;
    }

    public void setRefreshExpiration(int refreshExpiration) {
        this.refreshExpiration = refreshExpiration;
    }

    public int getTempExpiration() {
        return tempExpiration;
    }

    public void setTempExpiration(int tempExpiration) {
        this.tempExpiration = tempExpiration;
    }

    public int getRecoveryExpiration() {
        return recoveryExpiration;
    }

    public void setRecoveryExpiration(int recoveryExpiration) {
        this.recoveryExpiration = recoveryExpiration;
    }

    public static class KeyConfig {
        private String oldkeyId;
        private String newkeyId;
        private String oldkey;
        private String newkey;

        public String getOldkeyId() {
            return oldkeyId;
        }

        public void setOldkeyId(String oldkeyId) {
            this.oldkeyId = oldkeyId;
        }

        public String getNewkeyId() {
            return newkeyId;
        }

        public void setNewkeyId(String newkeyId) {
            this.newkeyId = newkeyId;
        }

        public String getOldkey() {
            return oldkey;
        }

        public void setOldkey(String oldkey) {
            this.oldkey = oldkey;
        }

        public String getNewkey() {
            return newkey;
        }

        public void setNewkey(String newkey) {
            this.newkey = newkey;
        }
    }
}
