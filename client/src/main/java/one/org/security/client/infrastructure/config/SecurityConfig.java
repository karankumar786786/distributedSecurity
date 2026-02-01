package one.org.security.client.infrastructure.config;

import one.org.security.client.infrastructure.security.CustomAuthenticationFailureHandler;
import one.org.security.client.infrastructure.security.CustomAuthenticationSuccessHandler;
import one.org.security.client.infrastructure.security.HttpCookieOAuth2AuthorizationRequestRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomAuthenticationSuccessHandler successHandler;

    @Autowired
    private CustomAuthenticationFailureHandler failureHandler;

    @Bean
    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }

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
                                System.out.println("=== SETTING AUTHORIZATION REQUEST REPOSITORY ===");
                                authorization.authorizationRequestRepository(authorizationRequestRepository());
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
