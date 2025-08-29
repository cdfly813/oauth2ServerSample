package com.example.oauth2server.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import com.fasterxml.jackson.annotation.JsonInclude;

@Schema(description = "OAuth2 token response")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenResponse {

    @Schema(description = "Access token (JWT)", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    private String accessToken;

    @Schema(description = "Token type", example = "Bearer")
    private String tokenType;

    @Schema(description = "Access token expiration time in seconds", example = "3600")
    private Integer expiresIn;

    @Schema(description = "Refresh token", example = "refresh_token_here")
    private String refreshToken;

    @Schema(description = "Granted scope", example = "read write")
    private String scope;

    @Schema(description = "Error code (if request failed)", example = "invalid_request")
    private String error;

    @Schema(description = "Error description (if request failed)", example = "The request is missing a required parameter")
    private String errorDescription;

    // Default constructor
    public TokenResponse() {}

    // Constructor for successful response
    public TokenResponse(String accessToken, String tokenType, Integer expiresIn, String refreshToken, String scope) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
        this.refreshToken = refreshToken;
        this.scope = scope;
    }

    // Constructor for error response
    public TokenResponse(String error, String errorDescription) {
        this.error = error;
        this.errorDescription = errorDescription;
    }

    // Getters and setters
    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public Integer getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(Integer expiresIn) {
        this.expiresIn = expiresIn;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public void setErrorDescription(String errorDescription) {
        this.errorDescription = errorDescription;
    }
}
