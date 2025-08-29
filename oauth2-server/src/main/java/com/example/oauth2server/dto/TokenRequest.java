package com.example.oauth2server.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Token request for OAuth2 authorization")
public class TokenRequest {

    @Schema(description = "OAuth2 grant type", example = "authorization_code", allowableValues = {"authorization_code", "refresh_token", "client_credentials"})
    @NotBlank(message = "Grant type is required")
    private String grantType;

    @Schema(description = "Authorization code (for authorization_code grant)", example = "abc123def456")
    private String code;

    @Schema(description = "Refresh token (for refresh_token grant)", example = "refresh_token_here")
    private String refreshToken;

    @Schema(description = "Client ID", example = "client1")
    @NotBlank(message = "Client ID is required")
    private String clientId;

    @Schema(description = "Client secret", example = "secret1")
    @NotBlank(message = "Client secret is required")
    private String clientSecret;

    @Schema(description = "Redirect URI", example = "http://localhost:3000/callback")
    private String redirectUri;

    @Schema(description = "Requested scope", example = "read write")
    private String scope;

    // Default constructor
    public TokenRequest() {}

    // Getters and setters
    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }
}
