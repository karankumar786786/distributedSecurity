package one.org.security.core.service.Cache;


import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import one.org.security.api.dto.enums.OtpSentMethodEnum;
import one.org.security.core.domain.dto.OtpVerificationDTO;

@Service
public class RedisService {

    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    public boolean setOtpVerification(OtpVerificationDTO otpVerificationDTO) {
        String key = "verification:" + otpVerificationDTO.username();
        // The order is otp, deviceHash, to, method, attempts.
        String value = otpVerificationDTO.otp() + ":" + otpVerificationDTO.to()
                + ":" + otpVerificationDTO.method().toString() + ":" + otpVerificationDTO.attempts();
        stringRedisTemplate.opsForValue().set(key, value, 5, TimeUnit.MINUTES);
        return true;
    }

    public OtpVerificationDTO getOtpVerification(String username) {
        String key = "verification:" + username;
        String value = stringRedisTemplate.opsForValue().get(key);

        if (value == null || value.isEmpty()) {
            return null;
        }

        String[] parts = value.split(":");
        if (parts.length < 3) {
            return null;
        }
        int attempts = 0;
        if (parts.length > 3) {
            attempts = Integer.valueOf(parts[3]);
        }
        return new OtpVerificationDTO(
                username,
                Integer.valueOf(parts[0]),
                parts[1],
                OtpSentMethodEnum.valueOf(parts[2]),
                attempts);
    }

    public OtpVerificationDTO getOtpVerificationAndDelete(String username) {
        String key = "verification:" + username;
        String value = stringRedisTemplate.opsForValue().getAndDelete(key);
        if (value == null || value.isEmpty()) {
            return null;
        }

        String[] parts = value.split(":");
        if (parts.length < 3) {
            return null;
        }
        int attempts = 0;
        if (parts.length > 3) {
            attempts = Integer.valueOf(parts[3]);
        }
        return new OtpVerificationDTO(
                username,
                Integer.valueOf(parts[0]),
                parts[2],
                OtpSentMethodEnum.valueOf(parts[2]),
                attempts);
    }

    public boolean deleteOtpVerification(String username) {
        String key = "verification:" + username;
        return Boolean.TRUE.equals(stringRedisTemplate.delete(key));
    }

    public void setValue(String key, String value, long timeout, TimeUnit unit) {
        stringRedisTemplate.opsForValue().set(key, value, timeout, unit);
    }

    public String getValue(String key) {
        return stringRedisTemplate.opsForValue().get(key);
    }

    public boolean deleteValue(String key) {
        return Boolean.TRUE.equals(stringRedisTemplate.delete(key));
    }

    
}
