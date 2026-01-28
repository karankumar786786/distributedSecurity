package one.org.security.Autherization.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
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
                // 1. Explicitly capture ALL OIDC and OAuth2 paths
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) -> authorizationServer
                        .oidc(oidc -> oidc
                                .providerConfigurationEndpoint(providerConfiguration -> providerConfiguration
                                        .providerConfigurationCustomizer(config -> config.idTokenSigningAlgorithms(a -> {a.clear();a.add(SignatureAlgorithm.ES256.toString());})
                                                .scopes(scopes -> {
                                                    scopes.add("read");
                                                    scopes.add("write");
                                                    scopes.add("uid");
                                                    scopes.add("username");
                                                })))))
                .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                // 3. IMPORTANT: Your filters must run here to provide the Principal during
                // /authorize
                .addFilterBefore(processDeviceFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(sessionFilture(), ProcessDeviceFilter.class);

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain standardSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                // 4. Ensure endpoints handled by Order 1 are ignored here
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated())
                .addFilterBefore(processDeviceFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(sessionFilture(), ProcessDeviceFilter.class);

        return http.build();
    }
}