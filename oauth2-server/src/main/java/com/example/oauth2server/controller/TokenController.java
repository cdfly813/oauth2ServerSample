package com.example.oauth2server.controller;

import com.example.oauth2server.dto.TokenRequest;
import com.example.oauth2server.dto.TokenResponse;
import com.example.oauth2server.dto.TokenIntrospectionResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/oauth2")
@CrossOrigin(origins = "*")
@Tag(name = "OAuth2 Token Management", description = "JWT token operations including access tokens, refresh tokens, and token introspection")
public class TokenController {

    @Autowired(required = false)
    private OAuth2AuthorizationService authorizationService;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired(required = false)
    private OAuth2TokenGenerator<?> tokenGenerator;

    @PostMapping("/token")
    @Operation(summary = "Get access token", description = "Exchange authorization code, refresh token, or client credentials for an access token")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Token issued successfully",
            content = @Content(schema = @Schema(implementation = TokenResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid request or grant type",
            content = @Content(schema = @Schema(implementation = TokenResponse.class))),
        @ApiResponse(responseCode = "401", description = "Invalid client credentials or authentication failed",
            content = @Content(schema = @Schema(implementation = TokenResponse.class)))
    })
    public ResponseEntity<TokenResponse> getToken(
            @Parameter(description = "OAuth2 token request parameters")
            @Valid @RequestBody TokenRequest tokenRequest,
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader,
            Principal principal) {

        try {
            // Validate client credentials
            RegisteredClient client = validateClientCredentials(tokenRequest, authorizationHeader);
            if (client == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new TokenResponse("invalid_client", "Invalid client credentials"));
            }

            TokenResponse response;

            switch (tokenRequest.getGrantType()) {
                case "authorization_code":
                    response = handleAuthorizationCodeGrant(tokenRequest, client);
                    break;
                case "refresh_token":
                    response = handleRefreshTokenGrant(tokenRequest, client);
                    break;
                case "client_credentials":
                    response = handleClientCredentialsGrant(tokenRequest, client);
                    break;
                default:
                    response = new TokenResponse("unsupported_grant_type",
                        "The grant type '" + tokenRequest.getGrantType() + "' is not supported");
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new TokenResponse("invalid_request", e.getMessage()));
        }
    }

    @PostMapping("/token/refresh")
    @Operation(summary = "Refresh access token", description = "Exchange a refresh token for a new access token")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "New tokens issued successfully",
            content = @Content(schema = @Schema(implementation = TokenResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid refresh token",
            content = @Content(schema = @Schema(implementation = TokenResponse.class))),
        @ApiResponse(responseCode = "401", description = "Refresh token expired or invalid")
    })
    public ResponseEntity<TokenResponse> refreshToken(
            @Parameter(description = "Refresh token request")
            @Valid @RequestBody TokenRequest tokenRequest,
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader) {

        // For refresh token, we can reuse the main token endpoint logic
        tokenRequest.setGrantType("refresh_token");
        return getToken(tokenRequest, authorizationHeader, null);
    }

    @PostMapping("/introspect")
    @Operation(summary = "Introspect token", description = "Check if a token is valid and get its metadata")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Token introspection successful",
            content = @Content(schema = @Schema(implementation = TokenIntrospectionResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid request or token",
            content = @Content(schema = @Schema(implementation = TokenIntrospectionResponse.class))),
        @ApiResponse(responseCode = "401", description = "Invalid client credentials")
    })
    public ResponseEntity<TokenIntrospectionResponse> introspectToken(
            @Parameter(description = "Token to introspect", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
            @RequestParam String token,
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader) {

        try {
            // For now, return a basic inactive response
            // In a full implementation, you'd validate the JWT token
            TokenIntrospectionResponse response = new TokenIntrospectionResponse(false, "invalid_token", "Token validation not implemented");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            TokenIntrospectionResponse errorResponse = new TokenIntrospectionResponse(false, "invalid_request", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    @GetMapping("/authorize")
    @Operation(summary = "OAuth2 Authorization Endpoint", description = "Initiate OAuth2 authorization code flow. This endpoint redirects to login page if not authenticated, then redirects back with authorization code.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "302", description = "Redirect to login page or back to client with authorization code"),
        @ApiResponse(responseCode = "400", description = "Invalid request parameters"),
        @ApiResponse(responseCode = "401", description = "Client authentication failed")
    })
    public ResponseEntity<String> authorizeEndpoint(
            @Parameter(description = "OAuth2 response type (e.g., code, token, id_token)", example = "code")
            @RequestParam String response_type,

            @Parameter(description = "Client ID registered with the authorization server", example = "client1")
            @RequestParam String client_id,

            @Parameter(description = "Redirect URI where the authorization code will be sent", example = "http://localhost:3000/callback")
            @RequestParam String redirect_uri,

            @Parameter(description = "Requested OAuth2 scopes (space-separated)", example = "read write")
            @RequestParam(required = false) String scope,

            @Parameter(description = "State parameter for CSRF protection", example = "xyz123")
            @RequestParam(required = false) String state,

            @Parameter(description = "OIDC nonce parameter", example = "abc123")
            @RequestParam(required = false) String nonce) {

        // This is just for documentation - the actual OAuth2 authorization flow
        // is handled by Spring Security OAuth2 Authorization Server
        return ResponseEntity.ok()
            .header("Content-Type", "text/html")
            .body("<html><body><h2>OAuth2 Authorization Documentation</h2>" +
                  "<p>This endpoint initiates the OAuth2 authorization code flow:</p>" +
                  "<ul>" +
                  "<li><strong>response_type:</strong> " + response_type + "</li>" +
                  "<li><strong>client_id:</strong> " + client_id + "</li>" +
                  "<li><strong>redirect_uri:</strong> " + redirect_uri + "</li>" +
                  "<li><strong>scope:</strong> " + (scope != null ? scope : "read") + "</li>" +
                  "<li><strong>state:</strong> " + (state != null ? state : "not provided") + "</li>" +
                  "</ul>" +
                  "<p>In a real OAuth2 flow, this would redirect to the login page or return an authorization code.</p>" +
                  "</body></html>");
    }

    @GetMapping("/.well-known/openid_configuration")
    @Operation(summary = "OpenID Connect configuration", description = "Get OpenID Connect provider configuration")
    @ApiResponse(responseCode = "200", description = "OIDC configuration returned successfully")
    public ResponseEntity<Map<String, Object>> getOpenIdConfiguration() {
        Map<String, Object> config = new HashMap<>();
        config.put("issuer", "http://localhost:8080");
        config.put("authorization_endpoint", "http://localhost:8080/oauth2/authorize");
        config.put("token_endpoint", "http://localhost:8080/oauth2/token");
        config.put("token_endpoint_auth_methods_supported", new String[]{"client_secret_basic", "client_secret_post"});
        config.put("token_endpoint_auth_signing_alg_values_supported", new String[]{"RS256"});
        config.put("userinfo_endpoint", "http://localhost:8080/userinfo");
        config.put("end_session_endpoint", "http://localhost:8080/logout");
        config.put("jwks_uri", "http://localhost:8080/oauth2/jwks");
        config.put("scopes_supported", new String[]{"openid", "profile", "email", "read", "write"});
        config.put("response_types_supported", new String[]{"code", "token", "id_token"});
        config.put("grant_types_supported", new String[]{"authorization_code", "refresh_token", "client_credentials"});
        config.put("subject_types_supported", new String[]{"public"});
        config.put("id_token_signing_alg_values_supported", new String[]{"RS256"});

        return ResponseEntity.ok(config);
    }

    private RegisteredClient validateClientCredentials(TokenRequest tokenRequest, String authorizationHeader) {
        String clientId = tokenRequest.getClientId();
        String clientSecret = tokenRequest.getClientSecret();

        // Check Basic Auth header
        if (authorizationHeader != null && authorizationHeader.startsWith("Basic ")) {
            try {
                String base64Credentials = authorizationHeader.substring(6);
                String credentials = new String(Base64.getDecoder().decode(base64Credentials));
                String[] parts = credentials.split(":");
                if (parts.length == 2) {
                    clientId = parts[0];
                    clientSecret = parts[1];
                }
            } catch (Exception e) {
                return null;
            }
        }

        if (clientId == null || clientSecret == null) {
            return null;
        }

        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
        if (client != null && clientSecret.equals(client.getClientSecret())) {
            return client;
        }

        return null;
    }

    private TokenResponse handleAuthorizationCodeGrant(TokenRequest tokenRequest, RegisteredClient client) {
        // For demo purposes, create a simple token response
        // In a full implementation, you'd validate the authorization code
        String accessToken = generateMockJWT(tokenRequest.getClientId(), "testuser");
        String refreshToken = "refresh_token_" + System.currentTimeMillis();

        return new TokenResponse(accessToken, "Bearer", 3600, refreshToken, "read write");
    }

    private TokenResponse handleRefreshTokenGrant(TokenRequest tokenRequest, RegisteredClient client) {
        // For demo purposes, create a new token
        // In a full implementation, you'd validate the refresh token
        String accessToken = generateMockJWT(tokenRequest.getClientId(), "testuser");
        String refreshToken = "refresh_token_" + System.currentTimeMillis();

        return new TokenResponse(accessToken, "Bearer", 3600, refreshToken, "read write");
    }

    private TokenResponse handleClientCredentialsGrant(TokenRequest tokenRequest, RegisteredClient client) {
        // For demo purposes, create a client credentials token
        String accessToken = generateMockJWT(tokenRequest.getClientId(), null);

        return new TokenResponse(accessToken, "Bearer", 3600, null, "read write");
    }

    private String generateMockJWT(String clientId, String username) {
        // Generate a mock JWT for demonstration
        // In a real implementation, you'd use the OAuth2TokenGenerator
        long now = Instant.now().getEpochSecond();
        String header = Base64.getUrlEncoder().encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
        String payload = Base64.getUrlEncoder().encodeToString(
            String.format("{\"sub\":\"%s\",\"client_id\":\"%s\",\"iat\":%d,\"exp\":%d}",
                username != null ? username : clientId,
                clientId,
                now,
                now + 3600).getBytes());

        return header + "." + payload + ".mock_signature";
    }
}
