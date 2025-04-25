package com.flight.booking.controller;

import com.flight.booking.dto.AuthResponseDto;
import com.flight.booking.dto.LoginDto;
import com.flight.booking.dto.UserDto;
import com.flight.booking.model.Role;
import com.flight.booking.model.User;
import com.flight.booking.repository.RoleRepository;
import com.flight.booking.repository.UserRepository;
import com.flight.booking.security.TokenGenerator;
import jakarta.servlet.http.HttpServletResponse;
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


@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private AuthenticationManager authenticationManager;
    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;
    private TokenGenerator tokenGenerator;


    @Autowired
    public AuthController(AuthenticationManager authenticationManager,
                          UserRepository userRepository,
                          RoleRepository roleRepository,
                          PasswordEncoder passwordEncoder,
                          TokenGenerator tokenGenerator) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenGenerator = tokenGenerator;
    }

    @PostMapping("/register")
public ResponseEntity<String> register(@RequestBody UserDto userDto) {
    User user = new User();
    user.setUsername(userDto.getUsername());
    user.setPassword(passwordEncoder.encode(userDto.getPassword()));
    user.setEmail(userDto.getEmail());

    // Determine the role
    String roleInput = userDto.getRole();
    final String roleName;

    if (roleInput == null || roleInput.trim().isEmpty()) {
        roleName = "ROLE_USER"; // Default role
    } else {
        String tempRoleName = roleInput.trim().toUpperCase();
        if (!tempRoleName.startsWith("ROLE_")) {
            tempRoleName = "ROLE_" + tempRoleName;
        }
        roleName = tempRoleName;
    }

    // Fetch the Role from the database
    Role role = roleRepository.findByName(roleName)
        .orElseThrow(() -> new RuntimeException("Role not found: " + roleName));

    user.setRole(role.getName());
    userRepository.save(user);

    return ResponseEntity.ok("User successfully registered!");
}



    public AuthResponseDto login(@RequestBody LoginDto loginDto,  HttpServletResponse response) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginDto.getUsername(), loginDto.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = tokenGenerator.generateToken(authentication);
        return new AuthResponseDto(token);
    }

    public ResponseEntity<AuthResponseDto> adminLogin(@RequestBody LoginDto loginDto) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginDto.getUsername(), loginDto.getPassword()));
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_ADMIN"));
        if (!isAdmin) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = tokenGenerator.generateToken(authentication);
        return new ResponseEntity<>(new AuthResponseDto(token), HttpStatus.OK);
    }
}

