package one.org.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;



@Service
@lombok.extern.slf4j.Slf4j
public class HmacService {
    private final byte[] oldKey;
    private final byte[] newKey;
    private final String oldKeyId;
    private final String newKeyId;

    public HmacService(
            @Value("${hmac.oldkey}") String oldKey,
            @Value("${hmac.newkey}") String newKey,
            @Value("${hmac.oldkeyId}") String oldKeyId,
            @Value("${hmac.newkeyId}") String newKeyId) {
        this.oldKey = oldKey.getBytes(StandardCharsets.UTF_8);
        this.newKey = newKey.getBytes(StandardCharsets.UTF_8);
        this.oldKeyId = oldKeyId;
        this.newKeyId = newKeyId;
    }

    public HmacDTO encode(String message) {
        String signature = performHash(message, this.newKey);
        return new HmacDTO(signature, null, this.newKeyId, null);
    }

    public boolean verify(@Validated HmacDTO hmacDTO) {
        byte[] keyToUse;
        if (newKeyId.equals(hmacDTO.keyId())) {
            keyToUse = newKey;
        } else if (oldKeyId.equals(hmacDTO.keyId())) {
            keyToUse = oldKey;
        } else {
            return false;
        }

        String expected = performHash(hmacDTO.message(), keyToUse);
        boolean matches = MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                hmacDTO.providedSignature().getBytes(StandardCharsets.UTF_8));
        if (!matches) {
            log.warn("HMAC mismatch! Message: '{}', Expected: '{}', Provided: '{}'", hmacDTO.message(), expected,
                    hmacDTO.providedSignature());
        }
        return matches;
    }

    private String performHash(String message, byte[] keyBytes) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
            byte[] signBytes = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signBytes);
        } catch (Exception e) {
            throw new IllegalStateException("Hmac sign failed", e);
        }
    }
}
