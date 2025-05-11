package com.vasan.Auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data // Lombok for getters/setters
@NoArgsConstructor // No-arg constructor
@AllArgsConstructor // All-args constructor
public class AuthenticationRequest {
    private String username; // Username for login
    private String password; // Plain password sent by client
}
