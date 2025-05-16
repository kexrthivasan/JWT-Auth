package com.vasan.Auth.security;

import com.vasan.Auth.service.UserDetailsServiceImpl;
import com.vasan.Auth.security.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component // Marks this class as a Spring-managed component
@RequiredArgsConstructor // Lombok generates a constructor with required arguments (i.e., final fields)
public class JwtRequestFilter extends OncePerRequestFilter {

    private final UserDetailsServiceImpl userDetailsService; // Service to load user details from DB
    private final JwtUtil jwtUtil; // Utility class for JWT operations like extract/validate

    /**
     * This method filters incoming HTTP requests and checks for a valid JWT token.
     * If a valid token is found, it sets the authentication in the SecurityContext.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // Get the Authorization header from the request
        final String authHeader = request.getHeader("Authorization");

        String username = null; // To hold the username extracted from the token
        String jwt = null;      // To hold the JWT token string

        // Check if the header is not null and starts with "Bearer "
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7); // Remove "Bearer " prefix to get the token
            username = jwtUtil.extractUsername(jwt); // Extract username from the token
        }

        // If a username is extracted and there is no authentication already set in context
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Load user details from the database using the username
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            // Validate the token using user details
            if (jwtUtil.validateToken(jwt, userDetails)) {
                // Create an authentication token containing user details and roles
                UsernamePasswordAuthenticationToken token =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                // Attach request details like IP and session ID
                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Set the authentication in the context for this request
                SecurityContextHolder.getContext().setAuthentication(token);
            }
        }

        // Continue processing the request through the remaining filters
        filterChain.doFilter(request, response);
    }
}
