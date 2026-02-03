package one.org.security.client.infrastructure.config;

import one.org.security.client.infrastructure.security.CustomAuthenticationFailureHandler;
import one.org.security.client.infrastructure.security.CustomAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Production-ready OAuth2 client configuration.
 * Uses Spring Security defaults - no unnecessary customization.
 * Works with ANY OAuth2 provider (Google, GitHub, custom servers).
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomAuthenticationSuccessHandler successHandler;

    @Autowired
    private CustomAuthenticationFailureHandler failureHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/", "/login", "/error").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                        .defaultSuccessUrl("/", true)
                // Spring's default HttpSessionOAuth2AuthorizationRequestRepository is used
                // No need for custom repository unless you have specific requirements
                );

        return http.build();
    }
}
