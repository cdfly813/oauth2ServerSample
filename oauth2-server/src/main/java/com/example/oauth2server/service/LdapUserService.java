package com.example.oauth2server.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.filter.Filter;
import org.springframework.stereotype.Service;

import javax.naming.directory.Attributes;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class LdapUserService {

    @Autowired
    private LdapTemplate ldapTemplate;

    public Map<String, Object> getUserByUsername(String username) {
        try {
            Filter filter = new EqualsFilter("uid", username);
            List<Attributes> results = ldapTemplate.search("ou=users", filter.encode(), 
                new UserAttributesMapper());

            if (results.isEmpty()) {
                return null;
            }

            Attributes userAttributes = results.get(0);
            Map<String, Object> userInfo = new HashMap<>();
            
            if (userAttributes.get("uid") != null) {
                userInfo.put("username", userAttributes.get("uid").get());
            }
            if (userAttributes.get("cn") != null) {
                userInfo.put("commonName", userAttributes.get("cn").get());
            }
            if (userAttributes.get("sn") != null) {
                userInfo.put("surname", userAttributes.get("sn").get());
            }
            if (userAttributes.get("givenName") != null) {
                userInfo.put("givenName", userAttributes.get("givenName").get());
            }
            if (userAttributes.get("mail") != null) {
                userInfo.put("email", userAttributes.get("mail").get());
            }

            // Get user groups
            List<String> groups = getUserGroups(username);
            userInfo.put("groups", groups);
            userInfo.put("roles", groups); // Groups serve as roles

            return userInfo;
        } catch (Exception e) {
            throw new RuntimeException("Error retrieving user: " + e.getMessage(), e);
        }
    }

    public List<String> getAllGroups() {
        try {
            List<String> groups = ldapTemplate.search("ou=groups", 
                "(objectClass=groupOfNames)", 
                new GroupAttributesMapper());
            return groups;
        } catch (Exception e) {
            throw new RuntimeException("Error retrieving groups: " + e.getMessage(), e);
        }
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



