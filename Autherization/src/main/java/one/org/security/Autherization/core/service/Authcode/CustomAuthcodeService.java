package one.org.security.Autherization.core.service.Authcode;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;

import one.org.security.Autherization.core.service.cache.RedisService;

@Service
public class CustomAuthcodeService implements OAuth2AuthorizationService {

    @Autowired
    private RedisService redisService;

    @Override
    public void save(OAuth2Authorization authorization) {
        redisService.saveAuthorization(authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        redisService.removeAuthorization(authorization);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return redisService.findById(id);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        return redisService.findByToken(token, tokenType);
    }
}
