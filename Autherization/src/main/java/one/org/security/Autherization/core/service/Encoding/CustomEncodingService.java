package one.org.security.Autherization.core.service.Encoding;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import one.org.security.common.PasswordEncoding.EncodingService;

@Component
public class CustomEncodingService implements PasswordEncoder {

    @Autowired
    private EncodingService encodingService;

    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) {
            return null;
        }
        return encodingService.encode(rawPassword.toString());
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null) {
            return false;
        }
        return encodingService.verify(rawPassword.toString(), encodedPassword);
    }
}