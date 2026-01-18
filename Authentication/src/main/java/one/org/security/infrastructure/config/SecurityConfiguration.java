package one.org.security.infrastructure.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

        @Autowired
        private one.org.security.infrastructure.security.filter.JwtAuthFilter jwtAuthFilter;

        @Autowired
        private one.org.security.infrastructure.security.filter.RawDeviceDataFilter rawDeviceDataFilter;

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
                http
                                .csrf(AbstractHttpConfigurer::disable)
                                .authorizeHttpRequests(
                                                auth -> auth
                                                                .requestMatchers(HttpMethod.POST, "/auth/register")
                                                                .permitAll()
                                                                .requestMatchers(HttpMethod.POST,
                                                                                "/auth/check-user-exist")
                                                                .permitAll()
                                                                .requestMatchers(HttpMethod.POST, "/auth/login")
                                                                .permitAll()
                                                                .requestMatchers(HttpMethod.POST,
                                                                                "/auth/forget-password")
                                                                .permitAll()
                                                                .requestMatchers(HttpMethod.POST,
                                                                                "/auth/verify-forget-password")
                                                                .permitAll()
                                                                .requestMatchers(HttpMethod.POST,
                                                                                "/auth/login/password")
                                                                .permitAll()
                                                                .requestMatchers(HttpMethod.POST,
                                                                                "/auth/login/fido/init")
                                                                .permitAll()
                                                                .requestMatchers(HttpMethod.POST,
                                                                                "/auth/login/fido/complete")
                                                                .permitAll()
                                                                .requestMatchers(HttpMethod.POST, "/auth/refresh")
                                                                .permitAll()
                                                                .requestMatchers("/fido-test.html", "/swagger-ui/**",
                                                                                "/v3/api-docs/**")
                                                                .permitAll()
                                                                .anyRequest().authenticated())
                                .addFilterBefore(rawDeviceDataFilter,
                                                org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class)
                                .addFilterAfter(jwtAuthFilter,
                                                one.org.security.infrastructure.security.filter.RawDeviceDataFilter.class);
                return http.build();
        }

}
