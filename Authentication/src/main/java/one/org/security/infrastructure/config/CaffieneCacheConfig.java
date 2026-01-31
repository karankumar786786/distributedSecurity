package one.org.security.infrastructure.config;

import java.util.concurrent.TimeUnit;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

@Configuration
public class CaffieneCacheConfig {
    @Bean
    public Cache<String, byte[]> keyCache(){
        return Caffeine.newBuilder()
                    .initialCapacity(100)
                    .maximumSize(500)
                    .expireAfterWrite(10,TimeUnit.MINUTES)
                    .recordStats()
                    .build();
    }
}
