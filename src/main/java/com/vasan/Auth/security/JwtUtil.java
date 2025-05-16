package com.vasan.Auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component // Marks this class as a Spring-managed component (bean), so it can be injected wherever needed
public class JwtUtil {

    // Secret key used to sign the JWT token (Important: keep this secure in production)
    private final String SECRET_KEY = "keerthivasandfghjfghjfghjfghjfghjghjghjghjghj";

    // Extract the username (stored as "subject") from the JWT token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Extract the token's expiration date
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Extract a specific claim from the token using a lambda function (e.g., subject, expiration)
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token); // Get all claims first
        return claimsResolver.apply(claims); // Apply the resolver function to return the specific claim
    }

    // Extract all claims from the token using the secret key
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY) // Use the secret key to parse the token
                .parseClaimsJws(token)     // Parse the token into a JWS (signed JWT)
                .getBody();                // Get the actual claims (payload)
    }

    // Check if the token has expired by comparing the expiration date with the current date
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Generate a new JWT token for a given user
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>(); // You can add custom claims like roles here
        return createToken(claims, userDetails.getUsername()); // Use username as the subject
    }

    // Create a JWT token with the provided claims, subject, issue time, and expiration time
    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims) // Set additional information if needed (e.g., roles)
                .setSubject(subject) // Subject is usually the username
                .setIssuedAt(new Date(System.currentTimeMillis())) // Token issue time
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // Expire in 10 hours
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY) // Sign the token with HMAC SHA256 algorithm
                .compact(); // Generate the compact JWT string
    }

    // Validate the token by checking:
    // 1. If the username in the token matches the user details
    // 2. If the token has not expired
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token); // Get the username from the token
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
