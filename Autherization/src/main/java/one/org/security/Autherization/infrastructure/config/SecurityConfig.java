package one.org.security.Autherization.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import one.org.security.Autherization.infrastructure.security.filture.SessionFilture;
import one.org.security.common.Filtures.ProcessDeviceFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SessionFilture sessionFilture(){
        return new SessionFilture();
    }

    @Bean
    public ProcessDeviceFilter processDeviceFilter(){
        return new ProcessDeviceFilter();
    }
    
    @Bean 
    public SecurityFilterChain securityFilterChain(HttpSecurity http){
        http
        .csrf(csrf -> csrf.disable())
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(
            autherize -> autherize.anyRequest().authenticated()
        )
        .addFilterBefore(processDeviceFilter(), UsernamePasswordAuthenticationFilter.class)
        .addFilterAfter(sessionFilture(), ProcessDeviceFilter.class);
        return http.build();
    }
}
