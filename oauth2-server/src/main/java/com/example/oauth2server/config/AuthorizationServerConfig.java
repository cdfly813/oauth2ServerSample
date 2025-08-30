package com.example.oauth2server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    @Autowired
    private org.springframework.ldap.core.support.LdapContextSource contextSource;

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/").permitAll()
            .requestMatchers("/login").permitAll()
            .requestMatchers("/oauth2/**").permitAll()
            .requestMatchers("/.well-known/**").permitAll()
            .requestMatchers("/swagger-ui/**").permitAll()
            .requestMatchers("/swagger-ui.html").permitAll()
            .requestMatchers("/api-docs/**").permitAll()
            .requestMatchers("/v3/api-docs/**").permitAll()
            .anyRequest().authenticated()
        );

        // Configure exception handling to redirect to login page
        http.exceptionHandling(exceptions -> exceptions
            .authenticationEntryPoint(new org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint("/login"))
        );

        // Configure the success handler with a default URL
        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setDefaultTargetUrl("/");
        successHandler.setAlwaysUseDefaultTargetUrl(false); // Only use default if no saved request
        successHandler.setTargetUrlParameter("continue");  // Handle 'continue' param for OAuth flows

        http.formLogin(form -> form
                .loginPage("/login")
                .successHandler(successHandler)
                .permitAll()
        );
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public LdapAuthenticationProvider ldapAuthenticationProvider() {
        // Use the embedded LDAP server configuration
        FilterBasedLdapUserSearch userSearch = new FilterBasedLdapUserSearch(
            "ou=users", "(uid={0})", contextSource);
        userSearch.setReturningAttributes(new String[]{"uid", "cn", "mail"});

        BindAuthenticator authenticator = new BindAuthenticator(contextSource);
        authenticator.setUserSearch(userSearch);

        LdapAuthenticationProvider provider = new LdapAuthenticationProvider(authenticator);
        provider.setUserDetailsContextMapper(new LdapUserDetailsMapper());
        return provider;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // Apply default OAuth2 authorization server security
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // Configure OIDC support
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults());

        // Configure authorization endpoint
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .authorizationEndpoint(authorizationEndpoint ->
                authorizationEndpoint
                    .consentPage("/oauth2/consent")
            );


        // In oauth2AuthorizationServerConfigurer (add this if not present)
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .tokenGenerator(tokenGenerator(jwkSource(), jwtTokenCustomizer()));  // Use customizer

        // Configure exception handling for OAuth2 endpoints
        http.exceptionHandling(exceptions -> exceptions
            .defaultAuthenticationEntryPointFor(
                new org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint("/login"),
                new org.springframework.security.web.util.matcher.AntPathRequestMatcher("/oauth2/authorize")
            )
        );

        return http.build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return (context) -> {
            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
                Authentication principal = context.getPrincipal();
                List<String> groups = principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .map(auth -> auth.replace("ROLE_", "").toLowerCase())  // e.g., "ROLE_ADMIN" -> "admin"
                        .collect(Collectors.toList());
                context.getClaims().claim("groups", groups);
            }
        };
    }


    // New helper bean for token generator
    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource, OAuth2TokenCustomizer<JwtEncodingContext> customizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        jwtGenerator.setJwtCustomizer(customizer);
        return new DelegatingOAuth2TokenGenerator(jwtGenerator);  // Add other generators if needed
    }


    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // H2M Client - Human-to-Machine (Authorization Code Flow)
        RegisteredClient h2mClient = RegisteredClient.withId("client1")
            .clientId("client1")
            .clientSecret(passwordEncoder().encode("secret1"))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("http://localhost:3000/callback")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope("read")
            .scope("write")
            .scope("user")
            .clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(false)
                .build())
            .tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofHours(1))
                .refreshTokenTimeToLive(Duration.ofDays(30))
                .build())
            .build();

        // M2M Client - Machine-to-Machine (Client Credentials Flow)
        RegisteredClient m2mClient = RegisteredClient.withId("client2")
            .clientId("client2")
            .clientSecret(passwordEncoder().encode("secret2"))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("read")
            .scope("write")
            .scope("api")
            .tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofHours(1))
                .build())
            .build();

        return new InMemoryRegisteredClientRepository(h2mClient, m2mClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
            .issuer("http://localhost:8080")
            .build();
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
}

