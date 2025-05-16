package com.vasan.Auth.security;

// Import custom service and filter
import com.vasan.Auth.service.UserDetailsServiceImpl;
import com.vasan.Auth.security.JwtRequestFilter;

// Lombok annotation to generate a constructor for final fields
import lombok.RequiredArgsConstructor;

// Spring framework and security-related imports
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

@Configuration // Marks this class as a configuration class
@RequiredArgsConstructor // Lombok generates a constructor for all final fields
public class SecurityConfig {

    // Custom service to load user details from database
    private final UserDetailsServiceImpl userDetailsService;

    // Custom JWT filter to validate tokens on every request
    private final JwtRequestFilter jwtRequestFilter;

    // Bean to encode passwords securely using BCrypt
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Bean to provide the AuthenticationManager, used during login
    @Bean
    public AuthenticationManager authManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    // Bean to define how authentication is handled (DAO + password encoder)
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService); // Set custom user details service
        provider.setPasswordEncoder(passwordEncoder());     // Set password encoder
        return provider;
    }

    // Main security configuration method
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // Disable CSRF (we're using JWT, so stateless)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll()  // Allow public access to login/register
                        .anyRequest().authenticated()                // All other requests require authentication
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // No session - JWT is stateless
                )
                .authenticationProvider(authenticationProvider()) // Use the custom authentication provider
                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class); // Add JWT filter before Spring’s auth filter

        return http.build(); // Return the configured security filter chain
    }
}
