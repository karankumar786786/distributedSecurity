package one.org.security.core.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import one.org.security.core.domain.dto.HmacDTO;
import one.org.security.core.domain.dto.TokenDTO;
import one.org.security.core.domain.enums.TokenPurposeMessageEnum;
import one.org.security.infrastructure.security.HmacService;
import one.org.security.infrastructure.security.JwtService;

@Service
public class VerifyUserService {
    @Autowired
    private JwtService jwtService;
    @Autowired
    private HmacService hmacService;

    public TokenDTO verifyUser(String token, String rawDeviceHash, TokenPurposeMessageEnum expectedPurpose) {
        TokenDTO tokenData = jwtService.decode(token, expectedPurpose);
        HmacDTO hmacDto = new HmacDTO(null, rawDeviceHash, tokenData.hmacKeyId(), tokenData.deviceHash());
        boolean verified = hmacService.verify(hmacDto);
        if (verified) {
            return tokenData;
        }
        return null;
    }
}
