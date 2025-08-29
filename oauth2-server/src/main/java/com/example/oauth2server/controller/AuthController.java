package com.example.oauth2server.controller;

import com.example.oauth2server.dto.LoginRequest;
import com.example.oauth2server.service.AuthenticationService;
import com.example.oauth2server.service.LdapUserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
@Tag(name = "Authentication", description = "Authentication and user management endpoints")
public class AuthController {

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private LdapUserService ldapUserService;

    @PostMapping("/login")
    @Operation(summary = "User login", description = "Authenticate user with username and password against LDAP")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Login successful",
            content = @Content(schema = @Schema(implementation = Map.class))),
        @ApiResponse(responseCode = "400", description = "Invalid credentials or validation error",
            content = @Content(schema = @Schema(implementation = Map.class))),
        @ApiResponse(responseCode = "401", description = "Authentication failed")
    })
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            Map<String, Object> result = authenticationService.authenticateUser(
                loginRequest.getUsername(), 
                loginRequest.getPassword()
            );

            if ((Boolean) result.get("success")) {
                return ResponseEntity.ok(result);
            } else {
                return ResponseEntity.badRequest().body(result);
            }
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<>();
            error.put("success", false);
            error.put("message", "Login error: " + e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @PostMapping("/register")
    @Operation(summary = "Register new user", description = "User registration is not supported via LDAP")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "400", description = "Registration not supported",
            content = @Content(schema = @Schema(implementation = Map.class)))
    })
    public ResponseEntity<?> registerUser(@RequestBody Map<String, String> userData) {
        Map<String, String> response = new HashMap<>();
        response.put("message", "User registration is not supported via LDAP. Please contact your administrator.");
        return ResponseEntity.badRequest().body(response);
    }

    @GetMapping("/user/{username}")
    @Operation(summary = "Get user information", description = "Retrieve user details from LDAP by username")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "User information retrieved successfully",
            content = @Content(schema = @Schema(implementation = Map.class))),
        @ApiResponse(responseCode = "404", description = "User not found"),
        @ApiResponse(responseCode = "400", description = "Bad request or error occurred")
    })
    public ResponseEntity<?> getUserInfo(
            @Parameter(description = "Username to search for", required = true)
            @PathVariable String username) {
        try {
            Map<String, Object> userInfo = ldapUserService.getUserByUsername(username);
            
            if (userInfo != null) {
                return ResponseEntity.ok(userInfo);
            } else {
                Map<String, String> error = new HashMap<>();
                error.put("error", "User not found");
                return ResponseEntity.notFound().build();
            }
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @GetMapping("/groups")
    @Operation(summary = "Get all groups", description = "Retrieve all available groups from LDAP")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Groups retrieved successfully",
            content = @Content(schema = @Schema(implementation = Map.class))),
        @ApiResponse(responseCode = "400", description = "Error occurred while retrieving groups")
    })
    public ResponseEntity<?> getAllGroups() {
        try {
            List<String> groups = ldapUserService.getAllGroups();
            Map<String, Object> response = new HashMap<>();
            response.put("groups", groups);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }
}



