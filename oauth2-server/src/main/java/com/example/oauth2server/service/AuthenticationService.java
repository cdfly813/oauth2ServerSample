package com.example.oauth2server.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.filter.Filter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.naming.directory.Attributes;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class AuthenticationService {

    @Autowired
    private LdapTemplate ldapTemplate;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public Map<String, Object> authenticateUser(String username, String password) {
        try {
            // First, verify the user exists and get their details
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            
            // Verify password against LDAP
            if (!verifyPasswordInLdap(username, password)) {
                throw new AuthenticationException("Invalid credentials") {};
            }

            // Create authentication token
            UsernamePasswordAuthenticationToken authToken = 
                new UsernamePasswordAuthenticationToken(username, password, userDetails.getAuthorities());

            // Return user information
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Authentication successful");
            response.put("username", username);
            response.put("authorities", userDetails.getAuthorities());
            
            // Get additional user info from LDAP
            Map<String, Object> userInfo = getUserInfoFromLdap(username);
            response.putAll(userInfo);

            return response;

        } catch (AuthenticationException e) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Authentication failed: " + e.getMessage());
            return response;
        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Authentication error: " + e.getMessage());
            return response;
        }
    }

    private boolean verifyPasswordInLdap(String username, String password) {
        try {
            // Create a filter to find the user
            Filter filter = new EqualsFilter("uid", username);
            
            // Search for the user
            List<Attributes> results = ldapTemplate.search("ou=users", filter.encode(), 
                new UserAttributesMapper());

            if (results.isEmpty()) {
                return false;
            }

            // For LDAP password verification, we need to attempt a bind
            // This is a simplified approach - in production you might want to use
            // Spring Security's LDAP authentication provider
            try {
                // Try to bind with the provided credentials
                ldapTemplate.getContextSource().getContext("uid=" + username + ",ou=users,dc=example,dc=com", password);
                return true;
            } catch (Exception e) {
                return false;
            }

        } catch (Exception e) {
            return false;
        }
    }

    private Map<String, Object> getUserInfoFromLdap(String username) {
        Map<String, Object> userInfo = new HashMap<>();
        
        try {
            Filter filter = new EqualsFilter("uid", username);
            List<Attributes> results = ldapTemplate.search("ou=users", filter.encode(), 
                new UserAttributesMapper());

            if (!results.isEmpty()) {
                Attributes attrs = results.get(0);
                
                if (attrs.get("cn") != null) {
                    userInfo.put("commonName", attrs.get("cn").get());
                }
                if (attrs.get("sn") != null) {
                    userInfo.put("surname", attrs.get("sn").get());
                }
                if (attrs.get("givenName") != null) {
                    userInfo.put("givenName", attrs.get("givenName").get());
                }
                if (attrs.get("mail") != null) {
                    userInfo.put("email", attrs.get("mail").get());
                }
            }

            // Get user groups
            List<String> groups = getUserGroups(username);
            userInfo.put("groups", groups);
            userInfo.put("roles", groups);

        } catch (Exception e) {
            // Log error but don't fail
            System.err.println("Error getting user info from LDAP: " + e.getMessage());
        }

        return userInfo;
    }

    private List<String> getUserGroups(String username) {
        try {
            Filter filter = new EqualsFilter("member", "uid=" + username + ",ou=users,dc=example,dc=com");
            List<String> groups = ldapTemplate.search("ou=groups", filter.encode(), 
                new GroupAttributesMapper());
            return groups;
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    private static class UserAttributesMapper implements org.springframework.ldap.core.AttributesMapper<Attributes> {
        @Override
        public Attributes mapFromAttributes(Attributes attributes) throws javax.naming.NamingException {
            return attributes;
        }
    }

    private static class GroupAttributesMapper implements org.springframework.ldap.core.AttributesMapper<String> {
        @Override
        public String mapFromAttributes(Attributes attributes) throws javax.naming.NamingException {
            return (String) attributes.get("ou").get();
        }
    }
}



