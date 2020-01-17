package com.san.polls.controller;

import java.net.URI;
import java.util.Collections;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.san.polls.exception.AppException;
import com.san.polls.model.Role;
import com.san.polls.model.RoleName;
import com.san.polls.model.User;
import com.san.polls.payload.ApiResponse;
import com.san.polls.payload.JwtAuthenticationResponse;
import com.san.polls.payload.LoginRequest;
import com.san.polls.payload.SignUpRequest;
import com.san.polls.repository.RoleRepository;
import com.san.polls.repository.UserRepository;
import com.san.polls.security.JwtTokenProvider;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

	@Autowired
    AuthenticationManager authenticationManager;
	
	@Autowired
    JwtTokenProvider tokenProvider;
	
	@Autowired
    UserRepository userRepository;
	
	@Autowired
    RoleRepository roleRepository;
	
	@Autowired
    PasswordEncoder passwordEncoder;
	
	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
		Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsernameOrEmail(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = tokenProvider.generateToken(authentication);
        return ResponseEntity.ok(new JwtAuthenticationResponse(jwt));
	}
	
	@PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        if(userRepository.existsByUsername(signUpRequest.getUsername())) {
            return new ResponseEntity(new ApiResponse(false, "Username is already taken!"), HttpStatus.BAD_REQUEST);
        }

        if(userRepository.existsByEmail(signUpRequest.getEmail())) {
            return new ResponseEntity(new ApiResponse(false, "Email Address already in use!"),
                    HttpStatus.BAD_REQUEST);
        }

        // Creating user's account
        User user = new User(signUpRequest.getName(), signUpRequest.getUsername(),
                signUpRequest.getEmail(), signUpRequest.getPassword());

        user.setPassword(passwordEncoder.encode(user.getPassword()));

        Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
                .orElseThrow(() -> new AppException("User Role not set."));

        user.setRoles(Collections.singleton(userRole));

        User result = userRepository.save(user);

        URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath().path("/api/users/{username}")
                .buildAndExpand(result.getUsername()).toUri();

        return ResponseEntity.created(location).body(new ApiResponse(true, "User registered successfully"));
    }
}
