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

@Component // Register this as a Spring bean
@RequiredArgsConstructor // Lombok will inject final fields
public class JwtRequestFilter extends OncePerRequestFilter {

    private final UserDetailsServiceImpl userDetailsService;
    private final JwtUtil jwtUtil;

    // This method is called for every request to check for a valid JWT token
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization"); // Get Authorization header
        String username = null;
        String jwt = null;

        // JWT token is expected to be in the format "Bearer <token>"
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7); // Extract token by removing "Bearer "
            username = jwtUtil.extractUsername(jwt); // Extract username from JWT
        }

        // If username is extracted and SecurityContext is not yet authenticated
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            // Validate token against user details
            if (jwtUtil.validateToken(jwt, userDetails)) {
                // Create authentication token and set it into SecurityContext
                UsernamePasswordAuthenticationToken token =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(token); // Authenticates the request
            }
        }

        // Pass the request along the filter chain
        filterChain.doFilter(request, response);


    }
}
