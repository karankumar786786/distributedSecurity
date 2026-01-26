package one.org.security.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import one.org.security.common.Filtures.ProcessDeviceFilter;
import one.org.security.infrastructure.security.filter.DeviceVerificationFilter;
import one.org.security.infrastructure.security.filter.ResendOtpVerificationOnAuthFilter;
import one.org.security.infrastructure.security.filter.SessionFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

        @Bean
        public ProcessDeviceFilter processDeviceFilter() {
                return new ProcessDeviceFilter();
        }

        @Bean
        public FilterRegistrationBean<ProcessDeviceFilter> processDeviceFilterRegistration(ProcessDeviceFilter filter) {
                FilterRegistrationBean<ProcessDeviceFilter> registration = new FilterRegistrationBean<>(filter);
                registration.setEnabled(false);
                return registration;
        }

       
       

        @Bean
        public DeviceVerificationFilter deviceVerificationFilter() {
                return new DeviceVerificationFilter();
        }

        @Bean
        public FilterRegistrationBean<DeviceVerificationFilter> deviceVerificationFilterRegistration(
                        DeviceVerificationFilter filter) {
                FilterRegistrationBean<DeviceVerificationFilter> registration = new FilterRegistrationBean<>(filter);
                registration.setEnabled(false);
                return registration;
        }

        @Bean
        public ResendOtpVerificationOnAuthFilter resendOtpVerificationOnAuthFilter() {
                return new ResendOtpVerificationOnAuthFilter();
        }

        @Bean
        public FilterRegistrationBean<ResendOtpVerificationOnAuthFilter> resendOtpVerificationOnAuthFilterRegistration(
                        ResendOtpVerificationOnAuthFilter filter) {
                FilterRegistrationBean<ResendOtpVerificationOnAuthFilter> registration = new FilterRegistrationBean<>(
                                filter);
                registration.setEnabled(false);
                return registration;
        }

        @Bean
        public SessionFilter sessionFilter() {
                return new SessionFilter();
        }

        @Bean
        public FilterRegistrationBean<SessionFilter> sessionFilterRegistration(SessionFilter filter) {
                FilterRegistrationBean<SessionFilter> registration = new FilterRegistrationBean<>(filter);
                registration.setEnabled(false);
                return registration;
        }

        @Bean
        @Order(1)
        public SecurityFilterChain filterChain1(HttpSecurity http) throws Exception {
                http
                                .securityMatcher("/auth/**")
                                .csrf(csrf -> csrf.disable())
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .authorizeHttpRequests(
                                                request -> request
                                                                .requestMatchers("/auth/**").permitAll()
                                                                .anyRequest().authenticated())
                                .addFilterBefore(processDeviceFilter(), UsernamePasswordAuthenticationFilter.class);
                return http.build();
        }

        @Bean
        @Order(2)
        public SecurityFilterChain filterChain2(HttpSecurity http) throws Exception {
                http
                                .securityMatcher("/init/**")
                                .csrf(csrf -> csrf.disable())
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .authorizeHttpRequests(
                                                request -> request
                                                                .requestMatchers(HttpMethod.POST,
                                                                                "/init/login/password")
                                                                .permitAll()
                                                                .requestMatchers(HttpMethod.POST,
                                                                                "/init/login/password/complete")
                                                                .permitAll()
                                                                .requestMatchers(HttpMethod.POST, "/init/login/fido")
                                                                .permitAll()
                                                                .requestMatchers(HttpMethod.POST,
                                                                                "/init/login/fido/complete")
                                                                .permitAll()
                                                                .requestMatchers(HttpMethod.GET,
                                                                                "/init/forget-password/backup-email")
                                                                .permitAll()
                                                                .requestMatchers(HttpMethod.POST,
                                                                                "/init/forget-password/backup-email/complete")
                                                                .permitAll()
                                                                .requestMatchers(HttpMethod.GET,
                                                                                "/init/forget-password/phone-number")
                                                                .permitAll()
                                                                .requestMatchers(HttpMethod.POST,
                                                                                "/init/forget-password/phone-number/complete")
                                                                .permitAll()
                                                                .requestMatchers(HttpMethod.POST,
                                                                                "/init/forget-password/resend-otp/phone-number")
                                                                .permitAll()
                                                                .requestMatchers(HttpMethod.POST,
                                                                                "/init/forget-password/resend-otp/backup-email")
                                                                .permitAll()
                                                                .anyRequest().authenticated())
                                .addFilterBefore(processDeviceFilter(), UsernamePasswordAuthenticationFilter.class)
                                .addFilterAfter(deviceVerificationFilter(), ProcessDeviceFilter.class);
                return http.build();
        }

        @Bean
        @Order(3)
        public SecurityFilterChain filterChain3(HttpSecurity http) throws Exception {
                http
                                .securityMatcher("/resend-otp/**")
                                .csrf(csrf -> csrf.disable())
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .authorizeHttpRequests(
                                                request -> request
                                                                .requestMatchers(HttpMethod.GET,
                                                                                "/resend-otp/forget-password/backup-email")
                                                                .permitAll()
                                                                .requestMatchers(HttpMethod.GET,
                                                                                "/resend-otp/forget-password/phone-number")
                                                                .permitAll()
                                                                .anyRequest().authenticated())
                                .addFilterBefore(processDeviceFilter(), UsernamePasswordAuthenticationFilter.class)
                                .addFilterAfter(resendOtpVerificationOnAuthFilter(), ProcessDeviceFilter.class);
                return http.build();
        }

        @Bean
        @Order(4)
        public SecurityFilterChain filterChain4(HttpSecurity http) throws Exception {
                http
                                .securityMatcher("/account/**")
                                .csrf(csrf -> csrf.disable())
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .authorizeHttpRequests(request -> request.anyRequest().authenticated())
                                .addFilterBefore(processDeviceFilter(), UsernamePasswordAuthenticationFilter.class)
                                .addFilterAfter(sessionFilter(), ProcessDeviceFilter.class);

                return http.build();
        }

        @Bean
        @Order(5)
        public SecurityFilterChain filterChain5(HttpSecurity http) throws Exception {
                http
                                .csrf(csrf -> csrf.disable())
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                                .authorizeHttpRequests(request -> request.requestMatchers("/fido-test.html", "/favicon.ico").permitAll().requestMatchers("/error").permitAll()
                                                .anyRequest().authenticated())
                                .addFilterBefore(processDeviceFilter(), UsernamePasswordAuthenticationFilter.class);
                return http.build();
        }

}
