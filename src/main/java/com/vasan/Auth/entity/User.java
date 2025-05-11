package com.vasan.Auth.entity;

import jakarta.persistence.*; // For entity annotations
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

// Lombok annotations to generate getters, setters, constructor, etc.
@Data // Generates getters and setters
@NoArgsConstructor // No-arg constructor
@AllArgsConstructor // All-args constructor

@Entity // Marks this class as a JPA entity
@Table(name = "users") // Maps this entity to the 'users' table in the DB
public class User {

    @Id // Primary key
    @GeneratedValue(strategy = GenerationType.IDENTITY) // Auto-increment ID
    private Long id;

    @Column(unique = true, nullable = false) // Username must be unique and not null
    private String username;

    @Column(nullable = false) // Password must not be null
    private String password; // Password should be stored encoded
}
