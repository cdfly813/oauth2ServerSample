package com.example.oauth2server.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.filter.Filter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.naming.directory.Attributes;
import java.util.ArrayList;
import java.util.List;
import org.springframework.ldap.core.AttributesMapper;

@Service
public class LdapUserDetailsService implements UserDetailsService {

    @Autowired
    private LdapTemplate ldapTemplate;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            // Search for user in LDAP
            Filter filter = new EqualsFilter("uid", username);
            List<Attributes> results = 
                ldapTemplate.search("ou=users", filter.encode(), new UserAttributesMapper());

            if (results.isEmpty()) {
                throw new UsernameNotFoundException("User not found: " + username);
            }

            Attributes userAttributes = results.get(0);
            String uid = (String) userAttributes.get("uid").get();
            String cn = (String) userAttributes.get("cn").get();
            
            // Get user groups (roles)
            List<SimpleGrantedAuthority> authorities = getUserAuthorities(uid);
            
            // For LDAP authentication, we don't store the password in UserDetails
            // The actual password verification happens during authentication
            return User.builder()
                .username(uid)
                .password("") // Empty password for LDAP users
                .authorities(authorities)
                .accountExpired(false)
                .accountLocked(false)
                .credentialsExpired(false)
                .disabled(false)
                .build();

        } catch (Exception e) {
            throw new UsernameNotFoundException("Error loading user: " + username, e);
        }
    }

    private List<SimpleGrantedAuthority> getUserAuthorities(String username) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        
        try {
            // Search for groups where the user is a member
            Filter filter = new EqualsFilter("member", "uid=" + username + ",ou=users,dc=example,dc=com");
            List<String> groups = ldapTemplate.search("ou=groups", filter.encode(), 
                (AttributesMapper<String>) attrs -> (String) attrs.get("ou").get());

            for (String group : groups) {
                authorities.add(new SimpleGrantedAuthority("GROUP_" + group));
                authorities.add(new SimpleGrantedAuthority("ROLE_" + group));
            }
        } catch (Exception e) {
            // Log error but don't fail user loading
            System.err.println("Error loading authorities for user " + username + ": " + e.getMessage());
        }
        
        return authorities;
    }

    private static class UserAttributesMapper implements org.springframework.ldap.core.AttributesMapper<Attributes> {
        @Override
        public Attributes mapFromAttributes(Attributes attributes) throws javax.naming.NamingException {
            return attributes;
        }
    }
}
