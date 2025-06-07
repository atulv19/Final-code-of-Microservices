package com.authservice.service;

import com.authservice.entity.User;
import com.authservice.payload.APIResponse;
import com.authservice.payload.UserDto;

import org.springframework.beans.BeanUtils;
import com.authservice.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public APIResponse<String> register(UserDto userDto) {
        APIResponse<String> response = new APIResponse<>();

        if (userRepository.existsByUsername(userDto.getUsername())) {
            response.setMessage("User registration failed");
            response.setStatus(409); // Conflict
            response.setData("User with this username already exists");
            return response;
        }

        if (userRepository.existsByEmail(userDto.getEmail())) {
            response.setMessage("User registration failed");
            response.setStatus(409); // Conflict
            response.setData("User with this email already exists");
            return response;
        }

        // Encrypt password
        String encryptedPassword = passwordEncoder.encode(userDto.getPassword());

// Create new user entity
        User user = new User();
        BeanUtils.copyProperties(userDto, user);

// Ensure ID is not copied (optional, if you want to avoid updating existing user)
        user.setId(null);

// Set encrypted password explicitly
        user.setPassword(encryptedPassword);
        user.setRole("ROLE_USER");

// Save to database
        User saveUser = userRepository.save(user);

// Handle failure (rare, but possible)
        if (saveUser == null) {
            response.setMessage("User registration failed");
            response.setStatus(500); // Internal Server Error
            response.setData("Unable to save user");
            return response;
        }

// Success response
        response.setMessage("User registered successfully");
        response.setStatus(201); // Created
        response.setData("Registration successful");
        return response;

    } 
}