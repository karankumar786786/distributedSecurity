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
        System.out.println("CustomEncodingService: encode called for " + rawPassword);
        if (rawPassword == null) {
            return null;
        }
        return encodingService.encode(rawPassword.toString());
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        System.out.println(
                "CustomEncodingService: matches called. Raw: " + rawPassword + ", Encoded: " + encodedPassword);
        if (rawPassword == null || encodedPassword == null) {
            return false;
        }
        boolean result = encodingService.verify(rawPassword.toString(), encodedPassword);
        System.out.println("CustomEncodingService: matches result: " + result);
        return result;
    }
}