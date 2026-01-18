package one.org.security.infrastructure.cache;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import one.org.security.core.domain.dto.OtpVerificationDTO;
import one.org.security.core.domain.enums.OtpSentMethodEnum;

@Service
public class RedisService {

    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    public boolean setOtpVerification(OtpVerificationDTO otpVerificationDTO) {
        String key = "verification:" + otpVerificationDTO.username();
        // Assuming OtpVerificationDTO now has an attempts() method and we want to add
        // it to the string.
        // The original instruction snippet was syntactically incorrect, so I'm
        // interpreting it as adding 'attempts' to the delimited string.
        // The order is otp, deviceHash, to, method, attempts.
        String value = otpVerificationDTO.otp() + ":" + otpVerificationDTO.deviceHash() + ":" + otpVerificationDTO.to()
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
        if (parts.length < 4) {
            return null;
        }
        int attempts = 0;
        if (parts.length > 4) {
            attempts = Integer.valueOf(parts[4]);
        }
        return new OtpVerificationDTO(
                username,
                parts[1],
                Integer.valueOf(parts[0]),
                parts[2],
                OtpSentMethodEnum.valueOf(parts[3]),
                attempts);
    }

    public OtpVerificationDTO getOtpVerificationAndDelete(String username) {
        String key = "verification:" + username;
        String value = stringRedisTemplate.opsForValue().getAndDelete(key);
        if (value == null || value.isEmpty()) {
            return null;
        }

        String[] parts = value.split(":");
        if (parts.length < 4) {
            return null;
        }
        int attempts = 0;
        if (parts.length > 4) {
            attempts = Integer.valueOf(parts[4]);
        }
        return new OtpVerificationDTO(
                username,
                parts[1],
                Integer.valueOf(parts[0]),
                parts[2],
                OtpSentMethodEnum.valueOf(parts[3]),
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
