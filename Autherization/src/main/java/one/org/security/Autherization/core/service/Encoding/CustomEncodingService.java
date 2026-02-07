package one.org.security.Autherization.core.service.Encoding;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Primary
@Slf4j
public class CustomEncodingService implements PasswordEncoder {

    @Autowired
    private HmacEncodingService hmacEncodingService;

    @Override
    public String encode(CharSequence rawPassword) {
        log.trace("CustomEncodingService: encode called");
        if (rawPassword == null) {
            return null;
        }
        return hmacEncodingService.encode(rawPassword.toString());
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        log.trace("CustomEncodingService: matches called");
        if (rawPassword == null || encodedPassword == null) {
            return false;
        }
        boolean result = hmacEncodingService.verify(encodedPassword, rawPassword.toString());
        log.trace("CustomEncodingService: matches result: {}", result);
        return result;
    }
}