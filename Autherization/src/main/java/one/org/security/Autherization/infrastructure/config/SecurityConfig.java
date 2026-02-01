package one.org.security.Autherization.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import org.springframework.http.MediaType;

import one.org.security.Autherization.infrastructure.security.filture.SessionFilture;
import one.org.security.Autherization.infrastructure.security.filture.LoggingFilter;
import one.org.security.Autherization.infrastructure.security.filture.TokenEndpointLoggingFilter;
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
        public LoggingFilter loggingFilter() {
                return new LoggingFilter();
        }

        @Bean
        public TokenEndpointLoggingFilter tokenEndpointLoggingFilter() {
                return new TokenEndpointLoggingFilter();
        }

        @Bean
        @Order(1)
        public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
                OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
                authorizationServerConfigurer.authorizationEndpoint(
                                authorizationEndpoint -> authorizationEndpoint.consentPage("/oauth2/consent"));

                http
                                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                                .requestCache(cache -> cache.disable())
                                .csrf(csrf -> csrf.ignoringRequestMatchers(
                                                authorizationServerConfigurer.getEndpointsMatcher()))
                                .with(authorizationServerConfigurer, (authorizationServer) -> authorizationServer
                                                .authorizationEndpoint(auth -> auth.consentPage("/oauth2/consent"))
                                                .oidc(oidc -> oidc
                                                                .providerConfigurationEndpoint(
                                                                                providerConfiguration -> providerConfiguration
                                                                                                .providerConfigurationCustomizer(
                                                                                                                config -> config.idTokenSigningAlgorithms(
                                                                                                                                a -> {
                                                                                                                                        a.clear();
                                                                                                                                        a.add(SignatureAlgorithm.RS256
                                                                                                                                                        .toString());
                                                                                                                                })
                                                                                                                                .scopes(scopes -> {
                                                                                                                                        scopes.add("read");
                                                                                                                                        scopes.add("write");
                                                                                                                                        scopes.add("username");
                                                                                                                                        scopes.add("profile");
                                                                                                                                        scopes.add("personaldata");
                                                                                                                                })))))
                                .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .exceptionHandling(exceptions -> exceptions
                                                .defaultAuthenticationEntryPointFor(
                                                                new one.org.security.Autherization.infrastructure.security.LoggingAuthenticationEntryPoint(
                                                                                "http://localhost:5713/login"),
                                                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                                // 3. IMPORTANT: Your filters must run here to provide the Principal during
                                // /authorize
                                // Using HeaderWriterFilter as anchor as it is standard in the chain
                                .addFilterAfter(processDeviceFilter(),
                                                org.springframework.security.web.header.HeaderWriterFilter.class)
                                .addFilterAfter(sessionFilture(), ProcessDeviceFilter.class)
                                .addFilterAfter(tokenEndpointLoggingFilter(), SessionFilture.class)
                                .addFilterAfter(new one.org.security.Autherization.infrastructure.security.filture.DebugFilter(),
                                                TokenEndpointLoggingFilter.class);
                return http.build();
        }

        @Bean
        @Order(2)
        public SecurityFilterChain standardSecurityFilterChain(HttpSecurity http) throws Exception {
                http
                                .csrf(csrf -> csrf.disable())
                                .formLogin(org.springframework.security.config.Customizer.withDefaults()) // Enable
                                                                                                          // default
                                                                                                          // login page
                                // 4. Ensure endpoints handled by Order 1 are ignored here
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .authorizeHttpRequests(authorize -> authorize
                                                .requestMatchers("/key/client/**").permitAll()
                                                .requestMatchers("/debug/**").permitAll()
                                                .requestMatchers("/login").permitAll() // Explicitly permit login
                                                .requestMatchers("/error").permitAll()
                                                .anyRequest().authenticated())
                                .addFilterBefore(processDeviceFilter(), UsernamePasswordAuthenticationFilter.class)
                                .addFilterAfter(sessionFilture(), ProcessDeviceFilter.class);

                return http.build();
        }
}