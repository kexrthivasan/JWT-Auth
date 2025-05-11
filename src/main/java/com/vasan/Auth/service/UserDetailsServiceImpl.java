package com.vasan.Auth.service;

import com.vasan.Auth.entity.User;
import com.vasan.Auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service // Registers this class as a Spring-managed service
@RequiredArgsConstructor // Lombok creates a constructor for the final userRepository
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    // Loads the user from the database using their username
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Fetch user from DB; throw exception if not found
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Return Spring Security compatible user object with at least one role
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")) // ✅ Add default authority
        );
    }
}
