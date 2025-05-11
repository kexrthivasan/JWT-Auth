package com.vasan.Auth.repository;

import com.vasan.Auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    // Spring Data JPA will auto-implement this to find user by username
    Optional<User> findByUsername(String username);
}
