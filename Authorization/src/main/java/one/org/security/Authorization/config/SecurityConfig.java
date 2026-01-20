package one.org.security.Authorization.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @org.springframework.beans.factory.annotation.Autowired
    private one.org.security.common.security.filter.JwtAuthFilter jwtAuthFilter;

    @org.springframework.beans.factory.annotation.Autowired
    private one.org.security.common.security.filter.RawDeviceDataFilter rawDeviceDataFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .addFilterBefore(rawDeviceDataFilter,
                        org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(jwtAuthFilter, one.org.security.common.security.filter.RawDeviceDataFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/oauth2/token").permitAll()
                        .requestMatchers("/oauth2/client/register", "/oauth2/authorize").authenticated()
                        .requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/actuator/**").permitAll()
                        .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    public org.springframework.boot.web.servlet.FilterRegistrationBean<one.org.security.common.security.filter.JwtAuthFilter> jwtAuthFilterRegistration(
            one.org.security.common.security.filter.JwtAuthFilter filter) {
        org.springframework.boot.web.servlet.FilterRegistrationBean<one.org.security.common.security.filter.JwtAuthFilter> registration = new org.springframework.boot.web.servlet.FilterRegistrationBean<>(
                filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public org.springframework.boot.web.servlet.FilterRegistrationBean<one.org.security.common.security.filter.RawDeviceDataFilter> rawDeviceDataFilterRegistration(
            one.org.security.common.security.filter.RawDeviceDataFilter filter) {
        org.springframework.boot.web.servlet.FilterRegistrationBean<one.org.security.common.security.filter.RawDeviceDataFilter> registration = new org.springframework.boot.web.servlet.FilterRegistrationBean<>(
                filter);
        registration.setEnabled(false);
        return registration;
    }
}
