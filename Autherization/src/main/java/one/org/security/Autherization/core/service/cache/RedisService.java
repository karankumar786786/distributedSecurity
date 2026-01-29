package one.org.security.Autherization.core.service.cache;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;

import one.org.security.Autherization.core.domain.entity.ClientEntity;

@Service
public class RedisService {
    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public RedisService() {
        ClassLoader classLoader = RedisService.class.getClassLoader();
        java.util.List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(securityModules);
        this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());

        // This is required to allow deserialization of the OAuth2Authorization class
        // which triggers the whitelist check.
        this.objectMapper.addMixIn(OAuth2Authorization.class, OAuth2AuthorizationMixin.class);
    }

    @com.fasterxml.jackson.annotation.JsonTypeInfo(use = com.fasterxml.jackson.annotation.JsonTypeInfo.Id.CLASS)
    public abstract static class OAuth2AuthorizationMixin {
    }

    public boolean saveClient(ClientEntity client) {
        try {
            String key = "client:" + client.getClientId();
            // id|userId|clientId|clientSecret|redirectUrl|writeAllowed
            String value = client.getId().toString() + "|" +
                    client.getUserId().toString() + "|" +
                    client.getClientId() + "|" +
                    client.getClientSecret() + "|" +
                    client.getRedirectUrl() + "|" +
                    client.isWriteAllowed();
            stringRedisTemplate.opsForValue().set(key, value, 15, java.util.concurrent.TimeUnit.MINUTES);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public ClientEntity getClient(String clientId) {
        try {
            String key = "client:" + clientId;
            String value = stringRedisTemplate.opsForValue().get(key);
            if (value != null) {
                String[] parts = value.split("\\|");
                if (parts.length >= 6) {
                    return ClientEntity.builder()
                            .id(new org.bson.types.ObjectId(parts[0]))
                            .userId(new org.bson.types.ObjectId(parts[1]))
                            .clientId(parts[2])
                            .clientSecret(parts[3])
                            .redirectUrl(parts[4])
                            .writeAllowed(Boolean.parseBoolean(parts[5]))
                            .build();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean deleteClient(String clientId) {
        try {
            String key = "client:" + clientId;
            return Boolean.TRUE.equals(stringRedisTemplate.delete(key));
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public void saveAuthorization(OAuth2Authorization authorization) {
        try {
            System.out.println("DEBUG: RedisService.saveAuthorization called for id: " + authorization.getId());
            String id = authorization.getId();
            String value = objectMapper.writeValueAsString(authorization);
            stringRedisTemplate.opsForValue().set("auth:id:" + id, value, 10, TimeUnit.MINUTES);
            System.out.println("DEBUG: Saved auth to redis with key: auth:id:" + id);

            if (authorization.getToken(OAuth2AuthorizationCode.class) != null) {
                OAuth2Authorization.Token<OAuth2AuthorizationCode> token = authorization
                        .getToken(OAuth2AuthorizationCode.class);
                stringRedisTemplate.opsForValue().set("auth:code:" + token.getToken().getTokenValue(), id, 10,
                        TimeUnit.MINUTES);
                System.out.println(
                        "DEBUG: Saved auth code mapping: auth:code:" + token.getToken().getTokenValue() + " -> " + id);
            }

            if (authorization.getRefreshToken() != null) {
                OAuth2RefreshToken token = authorization.getRefreshToken().getToken();
                stringRedisTemplate.opsForValue().set("auth:refresh_token:" + token.getTokenValue(), id, 10,
                        TimeUnit.MINUTES);
                System.out.println("DEBUG: Saved refresh token mapping: auth:refresh_token:" + token.getTokenValue()
                        + " -> " + id);
            }

            if (authorization.getAccessToken() != null) {
                OAuth2AccessToken token = authorization.getAccessToken().getToken();
                stringRedisTemplate.opsForValue().set("auth:access_token:" + token.getTokenValue(), id, 10,
                        TimeUnit.MINUTES);
                System.out.println(
                        "DEBUG: Saved access token mapping: auth:access_token:" + token.getTokenValue() + " -> " + id);
            }

            String state = authorization.getAttribute(OAuth2ParameterNames.STATE);
            if (state != null) {
                stringRedisTemplate.opsForValue().set("auth:state:" + state, id, 10, TimeUnit.MINUTES);
                System.out.println("DEBUG: Saved state mapping: auth:state:" + state + " -> " + id);
            }

        } catch (Exception e) {
            System.out.println("ERROR: RedisService.saveAuthorization failed: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public void removeAuthorization(OAuth2Authorization authorization) {
        System.out.println("DEBUG: RedisService.removeAuthorization called for id: " + authorization.getId());
        String id = authorization.getId();
        stringRedisTemplate.delete("auth:id:" + id);

        if (authorization.getToken(OAuth2AuthorizationCode.class) != null) {
            OAuth2Authorization.Token<OAuth2AuthorizationCode> token = authorization
                    .getToken(OAuth2AuthorizationCode.class);
            stringRedisTemplate.delete("auth:code:" + token.getToken().getTokenValue());
        }

        if (authorization.getRefreshToken() != null) {
            OAuth2RefreshToken token = authorization.getRefreshToken().getToken();
            stringRedisTemplate.delete("auth:refresh_token:" + token.getTokenValue());
        }

        if (authorization.getAccessToken() != null) {
            OAuth2AccessToken token = authorization.getAccessToken().getToken();
            stringRedisTemplate.delete("auth:access_token:" + token.getTokenValue());
        }

        String state = authorization.getAttribute(OAuth2ParameterNames.STATE);
        if (state != null) {
            stringRedisTemplate.delete("auth:state:" + state);
        }
    }

    public OAuth2Authorization findById(String id) {
        try {
            System.out.println("DEBUG: RedisService.findById called for id: " + id);
            String value = stringRedisTemplate.opsForValue().get("auth:id:" + id);
            if (value != null) {
                System.out.println("DEBUG: Found authorization for id: " + id);
                return objectMapper.readValue(value, OAuth2Authorization.class);
            } else {
                System.out.println("DEBUG: Authorization NOT found for id: " + id);
            }
        } catch (Exception e) {
            System.out.println("ERROR: RedisService.findById failed: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        System.out.println("DEBUG: RedisService.findByToken called. TokenType: "
                + (tokenType != null ? tokenType.getValue() : "null") + ", Token: " + token);
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

        System.out.println("DEBUG: Resolved ID from token/state: " + id);

        if (id != null) {
            return findById(id);
        }
        return null;
    }

}
