package one.org.security.Autherization.core.service.cache;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import one.org.security.Autherization.core.domain.entity.AuthorizationEntity;
import one.org.security.Autherization.core.domain.entity.ClientEntity;

@Service
@Slf4j
public class RedisService {
    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    private ObjectMapper objectMapper;

    public RedisService() {
    }

    @PostConstruct
    public void init() {
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    public boolean saveClient(ClientEntity client) {
        try {
            String key = "client:" + client.getClientId();
            // id|userId|clientId|clientSecret|redirectUrl|writeAllowed|showConsentForm|allowProfile|allowPersonalData
            StringBuilder value = new StringBuilder();
            value.append(client.getId().toString()).append("|")
                    .append(client.getUserId().toString()).append("|")
                    .append(client.getClientId()).append("|")
                    .append(client.getHashedClientSecretHmac()).append("|")
                    .append(client.getRedirectUrl()).append("|")
                    .append(client.isWriteAllowed()).append("|")
                    .append(client.isShowConsentForm()).append("|")
                    .append(client.isAllowProfile()).append("|")
                    .append(client.isAllowPersonalData());

            stringRedisTemplate.opsForValue().set(key, value.toString(), 15, java.util.concurrent.TimeUnit.MINUTES);
            return true;
        } catch (Exception e) {
            log.error("Error saving client to Redis", e);
            return false;
        }
    }

    public ClientEntity getClient(String clientId) {
        try {
            String key = "client:" + clientId;
            String value = stringRedisTemplate.opsForValue().get(key);
            if (value != null) {
                String[] parts = value.split("\\|");
                if (parts.length >= 9) {
                    return ClientEntity.builder()
                            .id(new org.bson.types.ObjectId(parts[0]))
                            .userId(new org.bson.types.ObjectId(parts[1]))
                            .clientId(parts[2])
                            .hashedClientSecretHmac(parts[3])
                            .redirectUrl(parts[4])
                            .writeAllowed(Boolean.parseBoolean(parts[5]))
                            .showConsentForm(Boolean.parseBoolean(parts[6]))
                            .allowProfile(Boolean.parseBoolean(parts[7]))
                            .allowPersonalData(Boolean.parseBoolean(parts[8]))
                            .build();
                }
            }
        } catch (Exception e) {
            log.error("Error getting client from Redis", e);
        }
        return null;
    }

    public boolean deleteClient(String clientId) {
        try {
            String key = "client:" + clientId;
            return Boolean.TRUE.equals(stringRedisTemplate.delete(key));
        } catch (Exception e) {
            log.error("Error deleting client from Redis", e);
            return false;
        }
    }

    public void saveAuthorizationEntity(AuthorizationEntity entity) {
        try {
            log.debug("RedisService.saveAuthorizationEntity called for id: {}", entity.getId());

            String value = objectMapper.writeValueAsString(entity);
            String id = entity.getId();

            stringRedisTemplate.opsForValue().set("auth:id:" + id, value, 10, TimeUnit.MINUTES);
            log.debug("Saved auth entity to redis as JSON. Key: auth:id:{}", id);

            // Same for indices - they just point to the ID
            if (entity.getAuthorizationCode() != null) {
                stringRedisTemplate.opsForValue().set("auth:code:" + entity.getAuthorizationCode().getTokenValue(), id,
                        10,
                        TimeUnit.MINUTES);
                log.debug("Saved auth code mapping: auth:code:{} -> {}",
                        "PRESENT", id); // Redacted
            }

            if (entity.getRefreshToken() != null) {
                stringRedisTemplate.opsForValue().set("auth:refresh_token:" + entity.getRefreshToken().getTokenValue(),
                        id, 10,
                        TimeUnit.MINUTES);
                log.debug("Saved refresh token mapping: auth:refresh_token:{} -> {}",
                        "PRESENT", id); // Redacted
            }

            if (entity.getAccessToken() != null) {
                stringRedisTemplate.opsForValue().set("auth:access_token:" + entity.getAccessToken().getTokenValue(),
                        id, 10,
                        TimeUnit.MINUTES);
                log.debug("Saved access token mapping: auth:access_token:{} -> {}",
                        "PRESENT", id); // Redacted
            }

            String state = entity.getState();
            if (state != null) {
                stringRedisTemplate.opsForValue().set("auth:state:" + state, id, 10, TimeUnit.MINUTES);
                log.debug("Saved tracking state mapping: auth:state:{} -> {}", state, id);
            }

            String clientState = entity.getClientState();
            if (clientState != null && !clientState.equals(state)) {
                stringRedisTemplate.opsForValue().set("auth:state:" + clientState, id, 10, TimeUnit.MINUTES);
                log.debug("Saved client state mapping: auth:state:{} -> {}", clientState, id);
            }

        } catch (Exception e) {
            log.error("RedisService.saveAuthorizationEntity failed", e);
            throw new RuntimeException(e);
        }
    }

    public void removeAuthorization(String id) {
        log.debug("RedisService.removeAuthorization called for id: {}", id);
        AuthorizationEntity entity = findAuthorizationEntityById(id);
        if (entity == null)
            return;

        stringRedisTemplate.delete("auth:id:" + id);

        if (entity.getAuthorizationCode() != null) {
            stringRedisTemplate.delete("auth:code:" + entity.getAuthorizationCode().getTokenValue());
        }

        if (entity.getRefreshToken() != null) {
            stringRedisTemplate.delete("auth:refresh_token:" + entity.getRefreshToken().getTokenValue());
        }

        if (entity.getAccessToken() != null) {
            stringRedisTemplate.delete("auth:access_token:" + entity.getAccessToken().getTokenValue());
        }

        if (entity.getState() != null) {
            stringRedisTemplate.delete("auth:state:" + entity.getState());
        }
    }

    public AuthorizationEntity findAuthorizationEntityById(String id) {
        try {
            log.debug("RedisService.findAuthorizationEntityById called for id: {}", id);
            String value = stringRedisTemplate.opsForValue().get("auth:id:" + id);
            if (value != null) {
                log.debug("Found JSON string for id: {}", id);
                return objectMapper.readValue(value, AuthorizationEntity.class);
            } else {
                log.debug("Authorization entity NOT found for id: {}", id);
            }
        } catch (Exception e) {
            log.error("RedisService.findAuthorizationEntityById failed", e);
        }
        return null;
    }

    public AuthorizationEntity findAuthorizationEntityByToken(String token, OAuth2TokenType tokenType) {
        try {
            log.debug("RedisService.findAuthorizationEntityByToken called. TokenType: {}, Token: {}",
                    (tokenType != null ? tokenType.getValue() : "null"), "REDACTED");

            if (tokenType == null) {
                return null;
            }
            String id = null;
            if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
                id = stringRedisTemplate.opsForValue().get("auth:state:" + token);
            } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
                id = stringRedisTemplate.opsForValue().get("auth:code:" + token);
            } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
                id = stringRedisTemplate.opsForValue().get("auth:access_token:" + token);
            } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
                id = stringRedisTemplate.opsForValue().get("auth:refresh_token:" + token);
            }

            log.debug("Resolved ID from token/state: {}", id);

            if (id != null) {
                return findAuthorizationEntityById(id);
            }
        } catch (Exception e) {
            log.error("RedisService.findAuthorizationEntityByToken CRASHED", e);
            throw e;
        }
        return null;
    }
}
