package one.org.security.Autherization.core.service.Encoding;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class CustomEncodingService implements PasswordEncoder {

    @Autowired
    private HmacEncodingService hmacEncodingService;

    @Override
    public String encode(CharSequence rawPassword) {
        System.out.println("CustomEncodingService: encode called for " + rawPassword);
        if (rawPassword == null) {
            return null;
        }
        return hmacEncodingService.encode(rawPassword.toString());
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        System.out.println(
                "CustomEncodingService: matches called. Raw: " + rawPassword + ", Encoded: " + encodedPassword);
        if (rawPassword == null || encodedPassword == null) {
            return false;
        }
        boolean result = hmacEncodingService.verify(rawPassword.toString(), encodedPassword);
        System.out.println("CustomEncodingService: matches result: " + result);
        return result;
    }
}