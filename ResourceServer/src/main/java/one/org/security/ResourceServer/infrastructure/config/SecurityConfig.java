package one.org.security.ResourceServer.infrastructure.config;

import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

        @Bean
        public JwtDecoder jwtDecoder(OAuth2ResourceServerProperties properties) {
                return NimbusJwtDecoder.withJwkSetUri(properties.getJwt().getJwkSetUri())
                                .jwsAlgorithm(SignatureAlgorithm.RS256)
                                .build();
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http
                                .csrf(csrf -> csrf.disable())
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .authorizeHttpRequests(
                                                authorize -> authorize
                                                                .requestMatchers(HttpMethod.GET, "/read")
                                                                .hasAnyAuthority("SCOPE_read")
                                                                .requestMatchers(HttpMethod.GET, "/write")
                                                                .hasAllAuthorities("SCOPE_write")
                                                                .requestMatchers(HttpMethod.GET, "/user/info")
                                                                .hasAnyAuthority("SCOPE_read", "SCOPE_openid")
                                                                .anyRequest().authenticated())
                                .oauth2ResourceServer(
                                                oauth2 -> oauth2.jwt(Customizer.withDefaults()));
                return http.build();
        }
}
