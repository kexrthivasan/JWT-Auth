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

@Component // Makes this class a Spring-managed utility bean
public class JwtUtil {

    // Secret key for signing the token (use a more secure key in production!)
    private final String SECRET_KEY = "keerthivasandfghjfghjfghjfghjfghjghjghjghjghj";

    // Extract username (subject) from token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Extract expiration date from token
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Extract a specific claim using a resolver function
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Helper method to extract all claims from a token
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY) // Set the signing key
                .parseClaimsJws(token)
                .getBody();
    }

    // Check if token has expired
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Generate token for user
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>(); // You can put roles or custom data here
        return createToken(claims, userDetails.getUsername());
    }

    // Create token using claims, subject and expiration
    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims) // Custom data
                .setSubject(subject) // Username
                .setIssuedAt(new Date(System.currentTimeMillis())) // Token issue time
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // Valid for 10 hours
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY) // Sign the token with HMAC SHA256
                .compact();
    }

    // Validate token against user details and check expiry
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token); // Extract username
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
