package com.authservice.controller;

import org.springframework.security.core.Authentication; // ✅ Correct import
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import com.authservice.payload.APIResponse;
import com.authservice.payload.LoginDto;
import com.authservice.payload.UserDto;
import com.authservice.service.AuthService;
import com.authservice.service.JwtService;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
	
	@Autowired
    private JwtService jwtService;

    @Autowired
    private AuthService authService;

    @Autowired
    private AuthenticationManager authManager;

    @PostMapping("/register")
    public ResponseEntity<APIResponse<String>> register(@RequestBody UserDto logindto) {
        APIResponse<String> response = authService.register(logindto);
        return new ResponseEntity<>(response, HttpStatusCode.valueOf(response.getStatus()));
    }


    @PostMapping("/login")
    public ResponseEntity<APIResponse<String>> loginCheck(@RequestBody LoginDto dto) {
        APIResponse<String> response = new APIResponse<>();

        UsernamePasswordAuthenticationToken token = 
            new UsernamePasswordAuthenticationToken(dto.getUsername(), dto.getPassword());

        try {
            Authentication authenticate = authManager.authenticate(token);
            if (authenticate.isAuthenticated()) {
                String jwtToken = jwtService.generateToken(dto.getUsername(),
                    authenticate.getAuthorities().iterator().next().getAuthority());

                response.setMessage("Login Successful");
                response.setStatus(200);
                response.setData(jwtToken);  // return JWT
                return new ResponseEntity<>(response, HttpStatusCode.valueOf(response.getStatus()));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        response.setMessage("Failed");
        response.setStatus(401);   
        response.setData("Unauthorized");
        return new ResponseEntity<>(response, HttpStatusCode.valueOf(response.getStatus()));
    }
}

//35:16
