package one.org.security.Autherization.core.service.cache;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;

import one.org.security.Autherization.core.domain.entity.AuthorizationEntity;
import one.org.security.Autherization.core.domain.entity.ClientEntity;

@Service
public class RedisService {
    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    public RedisService() {
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

    public void saveAuthorizationEntity(AuthorizationEntity entity) {
        try {
            System.out.println("DEBUG: RedisService.saveAuthorizationEntity called for id: " + entity.getId());

            // Strategy: Serialize the entire AuthorizationEntity to a Base64 string.
            // This satisfies the "store as string" requirement and safely handles all
            // nested complex types
            // (like OAuth2AuthorizationRequest in attributes) without JSON deserialization
            // issues.
            String value = serializeObject(entity);
            String id = entity.getId();

            stringRedisTemplate.opsForValue().set("auth:id:" + id, value, 10, TimeUnit.MINUTES);
            System.out.println("DEBUG: Saved auth entity to redis as BASE64 STRING. Key: auth:id:" + id);

            // Same for indices - they just point to the ID
            if (entity.getAuthorizationCode() != null) {
                stringRedisTemplate.opsForValue().set("auth:code:" + entity.getAuthorizationCode().getTokenValue(), id,
                        10,
                        TimeUnit.MINUTES);
                System.out.println("DEBUG: Saved auth code mapping: auth:code:"
                        + entity.getAuthorizationCode().getTokenValue() + " -> " + id);
            }

            if (entity.getRefreshToken() != null) {
                stringRedisTemplate.opsForValue().set("auth:refresh_token:" + entity.getRefreshToken().getTokenValue(),
                        id, 10,
                        TimeUnit.MINUTES);
                System.out.println("DEBUG: Saved refresh token mapping: auth:refresh_token:"
                        + entity.getRefreshToken().getTokenValue() + " -> " + id);
            }

            if (entity.getAccessToken() != null) {
                stringRedisTemplate.opsForValue().set("auth:access_token:" + entity.getAccessToken().getTokenValue(),
                        id, 10,
                        TimeUnit.MINUTES);
                System.out.println("DEBUG: Saved access token mapping: auth:access_token:"
                        + entity.getAccessToken().getTokenValue() + " -> " + id);
            }

            String state = entity.getState();
            if (state != null) {
                stringRedisTemplate.opsForValue().set("auth:state:" + state, id, 10, TimeUnit.MINUTES);
                System.out.println("DEBUG: Saved state mapping: auth:state:" + state + " -> " + id);
            }

        } catch (Exception e) {
            System.out.println("ERROR: RedisService.saveAuthorizationEntity failed: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public void removeAuthorization(String id) {
        System.out.println("DEBUG: RedisService.removeAuthorization called for id: " + id);
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

    // Helper to serialize any object to Base64 String
    private String serializeObject(java.io.Serializable obj) throws java.io.IOException {
        if (obj == null)
            return null;
        try (java.io.ByteArrayOutputStream sh = new java.io.ByteArrayOutputStream();
                java.io.ObjectOutputStream os = new java.io.ObjectOutputStream(sh)) {
            os.writeObject(obj);
            return java.util.Base64.getEncoder().encodeToString(sh.toByteArray());
        }
    }

    // Helper to deserialize Base64 String back to Object
    private Object deserializeObject(String str) throws java.io.IOException, ClassNotFoundException {
        if (str == null)
            return null;
        byte[] data = java.util.Base64.getDecoder().decode(str);
        try (java.io.ByteArrayInputStream sh = new java.io.ByteArrayInputStream(data);
                java.io.ObjectInputStream is = new java.io.ObjectInputStream(sh)) {
            return is.readObject();
        }
    }

    public AuthorizationEntity findAuthorizationEntityById(String id) {
        try {
            System.out.println("DEBUG: RedisService.findAuthorizationEntityById called for id: " + id);
            String value = stringRedisTemplate.opsForValue().get("auth:id:" + id);
            if (value != null) {
                System.out.println("DEBUG: Found base64 string for id: " + id);
                return (AuthorizationEntity) deserializeObject(value);
            } else {
                System.out.println("DEBUG: Authorization entity NOT found for id: " + id);
            }
        } catch (Exception e) {
            System.out.println("ERROR: RedisService.findAuthorizationEntityById failed: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

    public AuthorizationEntity findAuthorizationEntityByToken(String token, OAuth2TokenType tokenType) {
        try {
            System.out.println("DEBUG: RedisService.findAuthorizationEntityByToken called. TokenType: "
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
                return findAuthorizationEntityById(id);
            }
        } catch (Exception e) {
            System.out.println("ERROR: RedisService.findAuthorizationEntityByToken CRASHED: " + e.getMessage());
            e.printStackTrace();
            // Try to log to file as backup
            try (java.io.PrintWriter pw = new java.io.PrintWriter(
                    new java.io.FileWriter("/tmp/redis_crash.log", true))) {
                pw.println("Timestamp: " + java.time.Instant.now());
                e.printStackTrace(pw);
            } catch (Exception io) {
            }
            throw e; // Bubble up
        }
        return null;
    }

}
