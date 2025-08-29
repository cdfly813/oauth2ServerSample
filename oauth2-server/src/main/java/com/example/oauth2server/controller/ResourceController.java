package com.example.oauth2server.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
@Tag(name = "Resources", description = "Protected and public resource endpoints")
public class ResourceController {

    @GetMapping("/public/info")
    @Operation(summary = "Get public information", description = "Public endpoint that doesn't require authentication")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Public information retrieved successfully",
            content = @Content(schema = @Schema(implementation = Map.class)))
    })
    public ResponseEntity<?> getPublicInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("message", "This is public information");
        info.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(info);
    }

    @GetMapping("/user/profile")
    @Operation(summary = "Get user profile", description = "Protected endpoint for authenticated users (H2M)")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "User profile retrieved successfully",
            content = @Content(schema = @Schema(implementation = Map.class))),
        @ApiResponse(responseCode = "401", description = "Unauthorized - Authentication required"),
        @ApiResponse(responseCode = "403", description = "Forbidden - Insufficient permissions")
    })
    public ResponseEntity<?> getUserProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        Map<String, Object> profile = new HashMap<>();
        profile.put("message", "User profile accessed successfully");
        profile.put("username", authentication.getName());
        profile.put("authorities", authentication.getAuthorities().stream()
            .map(authority -> authority.getAuthority())
            .toList());
        profile.put("timestamp", System.currentTimeMillis());
        
        return ResponseEntity.ok(profile);
    }

    @GetMapping("/admin/users")
    @Operation(summary = "Get admin users", description = "Protected endpoint requiring ADMIN role (H2M)")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Admin users retrieved successfully",
            content = @Content(schema = @Schema(implementation = Map.class))),
        @ApiResponse(responseCode = "401", description = "Unauthorized - Authentication required"),
        @ApiResponse(responseCode = "403", description = "Forbidden - ADMIN role required")
    })
    public ResponseEntity<?> getAdminUsers() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Admin users endpoint accessed successfully");
        response.put("username", authentication.getName());
        response.put("authorities", authentication.getAuthorities().stream()
            .map(authority -> authority.getAuthority())
            .toList());
        response.put("timestamp", System.currentTimeMillis());
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/admin/roles")
    @Operation(summary = "Get admin roles", description = "Protected endpoint requiring ADMIN role (H2M)")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Admin roles retrieved successfully",
            content = @Content(schema = @Schema(implementation = Map.class))),
        @ApiResponse(responseCode = "401", description = "Unauthorized - Authentication required"),
        @ApiResponse(responseCode = "403", description = "Forbidden - ADMIN role required")
    })
    public ResponseEntity<?> getAdminRoles() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Admin roles endpoint accessed successfully");
        response.put("username", authentication.getName());
        response.put("authorities", authentication.getAuthorities().stream()
            .map(authority -> authority.getAuthority())
            .toList());
        response.put("timestamp", System.currentTimeMillis());
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/client/info")
    @Operation(summary = "Get client information", description = "Protected endpoint for M2M client credentials flow")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Client information retrieved successfully",
            content = @Content(schema = @Schema(implementation = Map.class))),
        @ApiResponse(responseCode = "401", description = "Unauthorized - Client authentication required"),
        @ApiResponse(responseCode = "403", description = "Forbidden - Insufficient client permissions")
    })
    public ResponseEntity<?> getClientInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Client credentials endpoint accessed successfully");
        response.put("clientId", authentication.getName());
        response.put("authorities", authentication.getAuthorities().stream()
            .map(authority -> authority.getAuthority())
            .toList());
        response.put("timestamp", System.currentTimeMillis());
        
        return ResponseEntity.ok(response);
    }
}



