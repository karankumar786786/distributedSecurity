package one.org.security.Autherization.infrastructure.config;

import org.springframework.security.config.Customizer;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import org.springframework.http.MediaType;

import one.org.security.Autherization.infrastructure.security.filture.SessionFilture;
import one.org.security.common.Filtures.ProcessDeviceFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SessionFilture sessionFilture() {
        return new SessionFilture();
    }

    @Bean
    public ProcessDeviceFilter processDeviceFilter() {
        return new ProcessDeviceFilter();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) -> authorizationServer
                        .oidc(Customizer.withDefaults()))
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated())
                // Redirect to your custom login page if session is missing
                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                // Add your device and session filters so OAuth2 knows who the user is
                .addFilterBefore(processDeviceFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(sessionFilture(), ProcessDeviceFilter.class);

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain standardSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        // Allow anyone to access the JWKS public keys
                        .requestMatchers("/.well-known/jwks.json", "/.well-known/openid-configuration").permitAll()
                        // Your management APIs require a session
                        .anyRequest().authenticated())
                // Apply your custom stateless session logic here as well
                .addFilterBefore(processDeviceFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(sessionFilture(), ProcessDeviceFilter.class);

        return http.build();
    }
}