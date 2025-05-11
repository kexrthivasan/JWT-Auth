package com.vasan.Auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data // Lombok generates getters/setters
@AllArgsConstructor // Constructor with token argument
public class AuthenticationResponse {
    private String token; // JWT token returned after successful authentication
}
