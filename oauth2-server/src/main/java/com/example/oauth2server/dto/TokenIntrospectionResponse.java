package com.example.oauth2server.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import com.fasterxml.jackson.annotation.JsonInclude;

@Schema(description = "Token introspection response")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenIntrospectionResponse {

    @Schema(description = "Whether the token is active", example = "true")
    private boolean active;

    @Schema(description = "Client ID associated with the token", example = "client1")
    private String clientId;

    @Schema(description = "Username associated with the token", example = "testuser")
    private String username;

    @Schema(description = "Token scope", example = "read write")
    private String scope;

    @Schema(description = "Token type", example = "Bearer")
    private String tokenType;

    @Schema(description = "Token expiration time (Unix timestamp)", example = "1640995200")
    private Long exp;

    @Schema(description = "Token issued at time (Unix timestamp)", example = "1640991600")
    private Long iat;

    @Schema(description = "Token not valid before time (Unix timestamp)", example = "1640991600")
    private Long nbf;

    @Schema(description = "Subject (user) identifier", example = "testuser")
    private String sub;

    @Schema(description = "Audience", example = "oauth2-server")
    private String aud;

    @Schema(description = "Issuer", example = "http://localhost:8080")
    private String iss;

    @Schema(description = "JWT ID", example = "unique-jwt-id")
    private String jti;

    @Schema(description = "Error code (if request failed)", example = "invalid_token")
    private String error;

    @Schema(description = "Error description (if request failed)", example = "The token is invalid or expired")
    private String errorDescription;

    // Default constructor
    public TokenIntrospectionResponse() {}

    // Constructor for active token
    public TokenIntrospectionResponse(boolean active, String clientId, String username, String scope,
                                    String tokenType, Long exp, Long iat, Long nbf, String sub, String aud,
                                    String iss, String jti) {
        this.active = active;
        this.clientId = clientId;
        this.username = username;
        this.scope = scope;
        this.tokenType = tokenType;
        this.exp = exp;
        this.iat = iat;
        this.nbf = nbf;
        this.sub = sub;
        this.aud = aud;
        this.iss = iss;
        this.jti = jti;
    }

    // Constructor for inactive/error token
    public TokenIntrospectionResponse(boolean active, String error, String errorDescription) {
        this.active = active;
        this.error = error;
        this.errorDescription = errorDescription;
    }

    // Getters and setters
    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public Long getExp() {
        return exp;
    }

    public void setExp(Long exp) {
        this.exp = exp;
    }

    public Long getIat() {
        return iat;
    }

    public void setIat(Long iat) {
        this.iat = iat;
    }

    public Long getNbf() {
        return nbf;
    }

    public void setNbf(Long nbf) {
        this.nbf = nbf;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
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
