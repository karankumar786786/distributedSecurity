package one.org.security.common.Hmac;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "hmac")
public class HmacProperties {
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
