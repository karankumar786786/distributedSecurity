package one.org.security.Autherization.core.service.Encoding;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.github.benmanes.caffeine.cache.Cache;

import lombok.extern.slf4j.Slf4j;
import one.org.security.Autherization.core.domain.entity.ClientHmacEntity;
import one.org.security.Autherization.infrastructure.persistance.ClientHmacRepository;
import one.org.security.common.util.EncryptionUtil;

@Service
@Slf4j
public class HmacEncodingService {

    private final String oldKeyId;
    private final String newKeyId;
    private final byte[] oldkey;
    private final byte[] newkey;

    @Autowired
    private EncryptionUtil encryptionUtil;

    @Autowired
    private Cache<String, byte[]> cache;

    @Autowired
    private ClientHmacRepository clientHmacRepository;

    public HmacEncodingService(
            @Value("${hmac.oldkeyId}") String oldkeyid,
            @Value("${hmac.newkeyId}") String newkeyid,
            @Value("${hmac.oldkey}") String oldkey,
            @Value("${hmac.newkey}") String newkey) {
        this.oldKeyId = oldkeyid;
        this.newKeyId = newkeyid;
        this.oldkey = oldkey.getBytes(StandardCharsets.UTF_8);
        this.newkey = newkey.getBytes(StandardCharsets.UTF_8);
    }

    public String encode(String rawData) {
        // encode in hmac using new key
        String signature = performHash(rawData, this.newkey);
        return signature + "|" + this.newKeyId;
    }

    public ClientHmacEntity createKey(String plainKey) {
        try {
            String encryptedKey = encryptionUtil.encrypt(plainKey);
            ClientHmacEntity keyEntity = new ClientHmacEntity(null, encryptedKey);
            return clientHmacRepository.save(keyEntity);
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt and save key", e);
        }
    }

    public boolean verify(String hashedData, String rawData) {
        if (hashedData == null || !hashedData.contains("|")) {
            return false;
        }
        String[] data = hashedData.split("\\|");
        if (data.length != 2) {
            return false;
        }
        String signature = data[0];
        String keyId = data[1];

        byte[] keyToUse = null;
        if (keyId.equals(this.newKeyId)) {
            keyToUse = this.newkey;
        } else if (keyId.equals(this.oldKeyId)) {
            keyToUse = this.oldkey;
        } else {
            byte[] cachedKey = cache.getIfPresent(keyId);
            if (cachedKey != null) {
                keyToUse = cachedKey;
            } else {
                Optional<ClientHmacEntity> byId = clientHmacRepository.findById(new ObjectId(keyId));
                if (byId.isPresent()) {
                    try {
                        String encryptedKey = byId.get().getEncryptedKey();
                        String decryptedKey = encryptionUtil.decrypt(encryptedKey);
                        keyToUse = decryptedKey.getBytes(StandardCharsets.UTF_8);
                        cache.put(keyId, keyToUse);
                    } catch (Exception e) {
                        log.error("Failed to decrypt security key for ID: {}", keyId, e);
                    }
                }
            }
        }

        if (keyToUse == null) {
            log.warn("HMAC Key not found for ID: {}", keyId);
            return false;
        }

        String calculatedHash = performHash(rawData, keyToUse);
        return calculatedHash.equals(signature);
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
