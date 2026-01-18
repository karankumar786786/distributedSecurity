package one.org.security.common.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import one.org.security.common.dto.HmacDTO;
import one.org.security.common.dto.TokenDTO;
import one.org.security.common.enums.TokenPurposeMessageEnum;

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
