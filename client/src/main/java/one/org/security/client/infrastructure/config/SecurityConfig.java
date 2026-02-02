package one.org.security.client.infrastructure.config;

import one.org.security.client.infrastructure.security.CustomAuthenticationFailureHandler;
import one.org.security.client.infrastructure.security.CustomAuthenticationSuccessHandler;
import one.org.security.client.infrastructure.security.HttpCookieOAuth2AuthorizationRequestRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security configuration for OAuth2 client.
 * Uses in-memory cache for authorization request storage - no cookies.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomAuthenticationSuccessHandler successHandler;

    @Autowired
    private CustomAuthenticationFailureHandler failureHandler;

    @Autowired
    private HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        System.out.println("=== CONFIGURING SECURITY FILTER CHAIN ===");
        http
                .authorizeHttpRequests(authorize -> {
                    System.out.println("=== CONFIGURING AUTHORIZATION RULES ===");
                    authorize
                            .requestMatchers("/", "/login", "/error").permitAll()
                            .anyRequest().authenticated();
                })
                .oauth2Login(oauth2 -> {
                    System.out.println("=== CONFIGURING OAUTH2 LOGIN ===");
                    oauth2
                            .authorizationEndpoint(authorization -> {
                                System.out
                                        .println("=== SETTING AUTHORIZATION REQUEST REPOSITORY (In-Memory Cache) ===");
                                authorization.authorizationRequestRepository(authorizationRequestRepository);
                            })
                            .successHandler(successHandler)
                            .failureHandler(failureHandler)
                            .defaultSuccessUrl("/", true);
                    System.out.println("=== OAUTH2 LOGIN CONFIGURED ===");
                });
        System.out.println("=== SECURITY FILTER CHAIN BUILT ===");
        return http.build();
    }
}
