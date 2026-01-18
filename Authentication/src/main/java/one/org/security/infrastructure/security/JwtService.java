package one.org.security.infrastructure.security;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import one.org.security.core.domain.dto.TokenDTO;
import one.org.security.core.domain.enums.TokenPurposeMessageEnum;

@Service
public class JwtService {

    private final String issuer;
    private final Map<TokenPurposeMessageEnum, KeySet> keyMap;

    private record KeySet(String oldKeyId, String newKeyId, byte[] oldKey, byte[] newKey) {
    }

    public JwtService(
            @Value("${jwt.issuer}") String issuer,
            // Access Keys
            @Value("${jwt.access.oldkeyId}") String accessOldKeyId,
            @Value("${jwt.access.newkeyId}") String accessNewKeyId,
            @Value("${jwt.access.oldkey}") String accessOldKey,
            @Value("${jwt.access.newkey}") String accessNewKey,
            // Refresh Keys
            @Value("${jwt.refresh.oldkeyId}") String refreshOldKeyId,
            @Value("${jwt.refresh.newkeyId}") String refreshNewKeyId,
            @Value("${jwt.refresh.oldkey}") String refreshOldKey,
            @Value("${jwt.refresh.newkey}") String refreshNewKey,
            // Temp/ForgetPassword Keys
            @Value("${jwt.temp.oldkeyId}") String tempOldKeyId,
            @Value("${jwt.temp.newkeyId}") String tempNewKeyId,
            @Value("${jwt.temp.oldkey}") String tempOldKey,
            @Value("${jwt.temp.newkey}") String tempNewKey) {

        this.issuer = issuer;
        this.keyMap = new HashMap<>();

        KeySet accessKeys = new KeySet(accessOldKeyId, accessNewKeyId,
                accessOldKey.getBytes(StandardCharsets.UTF_8), accessNewKey.getBytes(StandardCharsets.UTF_8));
        KeySet refreshKeys = new KeySet(refreshOldKeyId, refreshNewKeyId,
                refreshOldKey.getBytes(StandardCharsets.UTF_8), refreshNewKey.getBytes(StandardCharsets.UTF_8));
        KeySet tempKeys = new KeySet(tempOldKeyId, tempNewKeyId,
                tempOldKey.getBytes(StandardCharsets.UTF_8), tempNewKey.getBytes(StandardCharsets.UTF_8));

        this.keyMap.put(TokenPurposeMessageEnum.ACCESS_TOKEN, accessKeys);
        this.keyMap.put(TokenPurposeMessageEnum.REFRESH_TOKEN, refreshKeys);
        this.keyMap.put(TokenPurposeMessageEnum.TEMP_TOKEN, tempKeys);
        this.keyMap.put(TokenPurposeMessageEnum.FORGET_PASSWORD_VERIFICATION, tempKeys);
        this.keyMap.put(TokenPurposeMessageEnum.LOGIN, tempKeys);
        this.keyMap.put(TokenPurposeMessageEnum.LOGIN, tempKeys);
        this.keyMap.put(TokenPurposeMessageEnum.FORGET_PASSWORD, tempKeys);
    }

    public String encode(TokenDTO tokenDTO) {
        KeySet keys = keyMap.get(tokenDTO.purpose());
        if (keys == null) {
            throw new IllegalArgumentException("Unsupported token purpose: " + tokenDTO.purpose());
        }

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT)
                .keyID(keys.newKeyId())
                .customParam("issuer", this.issuer)
                .customParam("hmacKeyId", tokenDTO.hmacKeyId())
                .build();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(tokenDTO.subject())
                .issuer(this.issuer)
                .claim("id", tokenDTO.id())
                .claim("deviceHash", tokenDTO.deviceHash())
                .claim("purpose", tokenDTO.purpose())
                .issueTime(new Date())
                .expirationTime(
                        new Date(System.currentTimeMillis() + (tokenDTO.expirationAfterInMinutes() * 60 * 1000L)))
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        try {
            jwt.sign(new MACSigner(keys.newKey()));
        } catch (JOSEException e) {
            throw new RuntimeException("Error signing JWT", e);
        }
        return jwt.serialize();
    }
    public TokenDTO decode(String token, TokenPurposeMessageEnum expectedPurpose) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            String keyId = jwt.getHeader().getKeyID();

            KeySet keys = keyMap.get(expectedPurpose);
            if (keys == null) {
                throw new BadCredentialsException("Unsupported token purpose for verification");
            }

            byte[] keyToUse;
            if (keys.newKeyId().equals(keyId)) {
                keyToUse = keys.newKey();
            } else if (keys.oldKeyId().equals(keyId)) {
                keyToUse = keys.oldKey();
            } else {
                throw new BadCredentialsException("Invalid token key ID");
            }
            if (!jwt.verify(new MACVerifier(keyToUse))) {
                throw new BadCredentialsException("Invalid token signature");
            }
            System.out.println("here");

            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            String purpose = claims.getStringClaim("purpose");
            if (purpose == null || !purpose.equals(expectedPurpose.name())) {
                throw new BadCredentialsException("Invalid token purpose");
            }
            if (new Date().after(claims.getExpirationTime())) {
                throw new BadCredentialsException("Token expired");
            }

            String subject = claims.getSubject();
            String id = claims.getStringClaim("id");
            String deviceHash = claims.getStringClaim("deviceHash");
            String hmacKeyId = (String) jwt.getHeader().getCustomParam("hmacKeyId");

            long expTime = claims.getExpirationTime().getTime();
            long now = System.currentTimeMillis();
            int minutesRemaining = (int) ((expTime - now) / (1000 * 60));
            return new TokenDTO(subject, id, deviceHash, minutesRemaining, hmacKeyId, expectedPurpose);

        } catch (java.text.ParseException | JOSEException e) {
            throw new BadCredentialsException("Invalid token", e);
        }
    }
}
