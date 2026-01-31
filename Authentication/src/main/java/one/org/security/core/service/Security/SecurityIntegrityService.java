package one.org.security.core.service.Security;

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
import one.org.security.common.PasswordEncoding.EncodingService;
import one.org.security.common.util.EncryptionUtil;
import one.org.security.core.domain.dto.SecurityIntegrityDTO;
import one.org.security.core.domain.entity.FidoCredential;
import one.org.security.core.domain.entity.SecurityIntegrityFidoKeyEntity;
import one.org.security.core.domain.entity.SecurityIntegrityKeyEntity;
import one.org.security.infrastructure.persistence.SecurityIntegrityFidoKeyRepository;
import one.org.security.infrastructure.persistence.SecurityIntegrityKeyRepository;

@Service
@Slf4j
public class SecurityIntegrityService {

    private final byte[] oldKey;
    private final byte[] newKey;
    private final String oldKeyId;
    private final String newKeyId;

    private final byte[] fidoOldKey;
    private final byte[] fidoNewKey;
    private final String fidoOldKeyId;
    private final String fidoNewKeyId;

    @Autowired
    private SecurityIntegrityKeyRepository securityIntegrityKeyRepository;

    @Autowired
    private SecurityIntegrityFidoKeyRepository securityIntegrityFidoKeyRepository;

    @Autowired
    private EncodingService encodingService;

    @Autowired
    private EncryptionUtil encryptionUtil;

    @Autowired
    private Cache<String, byte[]> keyCache;

    public SecurityIntegrityService(
            @Value("${integrity.oldkey}") String oldkeyStr,
            @Value("${integrity.newkey}") String newkeyStr,
            @Value("${integrity.oldkeyId}") String oldkeyId,
            @Value("${integrity.newkeyId}") String newkeyId,
            @Value("${integrity.fidoOldkey}") String fidoOldkeyStr,
            @Value("${integrity.fidoNewkey}") String fidoNewkeyStr,
            @Value("${integrity.fidoOldkeyId}") String fidoOldkeyId,
            @Value("${integrity.fidoNewkeyId}") String fidoNewkeyId) {
        this.oldKey = oldkeyStr.getBytes(StandardCharsets.UTF_8);
        this.newKey = newkeyStr.getBytes(StandardCharsets.UTF_8);
        this.oldKeyId = oldkeyId;
        this.newKeyId = newkeyId;
        this.fidoOldKey = fidoOldkeyStr.getBytes(StandardCharsets.UTF_8);
        this.fidoNewKey = fidoNewkeyStr.getBytes(StandardCharsets.UTF_8);
        this.fidoOldKeyId = fidoOldkeyId;
        this.fidoNewKeyId = fidoNewkeyId;
    }

    public SecurityIntegrityDTO encode(SecurityIntegrityDTO securityIntegrity) {
        String integrityHmac = performHash(securityIntegrity.password(), this.newKey);
        String hashedPassword = encodingService.encode(securityIntegrity.password());
        return new SecurityIntegrityDTO(null, hashedPassword, integrityHmac, this.newKeyId);
    }

    public SecurityIntegrityKeyEntity createKey(String plainKey) {
        try {
            String encryptedKey = encryptionUtil.encrypt(plainKey);
            SecurityIntegrityKeyEntity keyEntity = SecurityIntegrityKeyEntity.builder().encryptedKey(encryptedKey)
                    .build();
            return securityIntegrityKeyRepository.save(keyEntity);
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt and save key", e);
        }
    }

    public SecurityIntegrityDTO verify(SecurityIntegrityDTO securityEntity) {
        byte[] keyToUse = null;

        if (newKeyId.equals(securityEntity.integrityHmacKeyId())) {
            keyToUse = this.newKey;
        } else if (oldKeyId.equals(securityEntity.integrityHmacKeyId())) {
            keyToUse = this.oldKey;
        } else {
            byte[] cachedKey = keyCache.getIfPresent(securityEntity.integrityHmacKeyId());
            if (cachedKey != null) {
                keyToUse = cachedKey;
            } else {
                Optional<SecurityIntegrityKeyEntity> byId = securityIntegrityKeyRepository
                        .findById(new ObjectId(securityEntity.integrityHmacKeyId()));
                if (byId.isPresent()) {
                    try {
                        String encryptedKey = byId.get().getEncryptedKey();
                        String decryptedKey = encryptionUtil.decrypt(encryptedKey);
                        keyToUse = decryptedKey.getBytes(StandardCharsets.UTF_8);
                        keyCache.put(securityEntity.integrityHmacKeyId(), keyToUse);
                    } catch (Exception e) {
                        log.error("Failed to decrypt security key for ID: {}", securityEntity.integrityHmacKeyId(), e);
                    }
                }
            }
        }

        if (keyToUse == null) {
            log.warn("Security Integrity Key not found or decryption failed for ID: {}",
                    securityEntity.integrityHmacKeyId());
            throw new SecurityException("Integrity check failed: Key not found");
        }

        String calculatedHash = performHash(securityEntity.password(), keyToUse);
        if (!calculatedHash.equals(securityEntity.integrityHmac())) {
            throw new SecurityException("Integrity check failed: Hash mismatch");
        }

        // If verified with an old key or a DB key, perform rotation to the new key
        if (!newKeyId.equals(securityEntity.integrityHmacKeyId())) {
            log.info("Rotating Security Integrity Key for user.");
            return encode(securityEntity);
        }

        return securityEntity;
    }

    public void encodeFido(FidoCredential credential) {
        String dataToSign = getFidoDataToSign(credential);
        String integrityHmac = performHash(dataToSign, this.fidoNewKey);
        credential.setIntegrityHmac(integrityHmac);
        credential.setIntegrityHmacKeyId(this.fidoNewKeyId);
    }

    public boolean verifyFido(FidoCredential credential) {
        byte[] keyToUse = null;
        String keyId = credential.getIntegrityHmacKeyId();

        if (fidoNewKeyId.equals(keyId)) {
            keyToUse = this.fidoNewKey;
        } else if (fidoOldKeyId.equals(keyId)) {
            keyToUse = this.fidoOldKey;
        } else {
            byte[] cachedKey = keyCache.getIfPresent(keyId);
            if (cachedKey != null) {
                keyToUse = cachedKey;
            } else {
                Optional<SecurityIntegrityFidoKeyEntity> byId = securityIntegrityFidoKeyRepository
                        .findById(new ObjectId(keyId));
                if (byId.isPresent()) {
                    keyToUse = byId.get().getKey().getBytes(StandardCharsets.UTF_8);
                    keyCache.put(keyId, keyToUse);
                }
            }
        }

        if (keyToUse == null) {
            log.warn("FIDO Integrity Key not found for ID: {}", keyId);
            return false;
        }

        String dataToVerify = getFidoDataToSign(credential);
        String calculatedHash = performHash(dataToVerify, keyToUse);

        if (!calculatedHash.equals(credential.getIntegrityHmac())) {
            return false;
        }

        // Rotation
        if (!fidoNewKeyId.equals(keyId)) {
            log.info("Rotating FIDO Integrity Key.");
            encodeFido(credential); // Update with new key
            return true; // Verified and rotated (caller needs to save the credential)
        }

        return true;
    }

    private String getFidoDataToSign(FidoCredential credential) {
        // Construct a string from immutable/identifying fields
        // Using Base64 or Hex representation of byte arrays to ensure consistency
        StringBuilder sb = new StringBuilder();
        if (credential.getCredentialId() != null)
            sb.append(Base64.getEncoder().encodeToString(credential.getCredentialId().getBytes()));
        if (credential.getUserHandle() != null)
            sb.append(Base64.getEncoder().encodeToString(credential.getUserHandle().getBytes()));
        if (credential.getPublicKey() != null)
            sb.append(Base64.getEncoder().encodeToString(credential.getPublicKey().getBytes()));
        return sb.toString();
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
