package com.example.oauth2server.config;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.*;
import com.unboundid.ldif.LDIFReader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

@Configuration
public class LdapConfig {

    private InMemoryDirectoryServer ldapServer;

    @Value("${spring.ldap.urls:ldap://localhost:1389}")
    private String ldapUrls;

    @Value("${spring.ldap.base:dc=example,dc=com}")
    private String ldapBase;

    @Value("${spring.ldap.username:cn=admin,dc=example,dc=com}")
    private String ldapUsername;

    @Value("${spring.ldap.password:admin}")
    private String ldapPassword;

    @PostConstruct
    public void startEmbeddedLdapServer() throws Exception {
        // Configure the embedded LDAP server
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(ldapBase);
        config.addAdditionalBindCredentials(ldapUsername, ldapPassword);
        config.setListenerConfigs(new InMemoryListenerConfig("default", null, 5389, null, null, null));

        // Create the LDAP server
        ldapServer = new InMemoryDirectoryServer(config);
        ldapServer.startListening();

        // Add test data
        addTestData();
    }

    @PreDestroy
    public void stopEmbeddedLdapServer() {
        if (ldapServer != null) {
            ldapServer.shutDown(true);
        }
    }

    private void addTestData() throws Exception {
        // LDIF data for test users and groups
        String ldifData = """
            dn: dc=example,dc=com
            objectClass: top
            objectClass: domain
            dc: example

            dn: ou=users,dc=example,dc=com
            objectClass: top
            objectClass: organizationalUnit
            ou: users

            dn: ou=groups,dc=example,dc=com
            objectClass: top
            objectClass: organizationalUnit
            ou: groups

            dn: uid=admin,ou=users,dc=example,dc=com
            objectClass: person
            objectClass: inetOrgPerson
            uid: admin
            cn: Admin User
            sn: Admin
            userPassword: admin
            mail: admin@example.com

            dn: uid=testuser,ou=users,dc=example,dc=com
            objectClass: person
            objectClass: inetOrgPerson
            uid: testuser
            cn: Test User
            sn: User
            userPassword: password
            mail: testuser@example.com

            dn: uid=john.doe,ou=users,dc=example,dc=com
            objectClass: person
            objectClass: inetOrgPerson
            uid: john.doe
            cn: John Doe
            sn: Doe
            userPassword: password
            mail: john.doe@example.com

            dn: cn=users,ou=groups,dc=example,dc=com
            objectClass: groupOfNames
            cn: users
            member: uid=admin,ou=users,dc=example,dc=com
            member: uid=testuser,ou=users,dc=example,dc=com
            member: uid=john.doe,ou=users,dc=example,dc=com

            dn: cn=admins,ou=groups,dc=example,dc=com
            objectClass: groupOfNames
            cn: admins
            member: uid=admin,ou=users,dc=example,dc=com
            """;

        try (LDIFReader reader = new LDIFReader(new ByteArrayInputStream(ldifData.getBytes(StandardCharsets.UTF_8)))) {
            Entry entry;
            while ((entry = reader.readEntry()) != null) {
                ldapServer.add(entry);
            }
        }
    }

    @Bean
    public LdapContextSource contextSource() {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(ldapUrls);
        contextSource.setBase(ldapBase);
        contextSource.setUserDn(ldapUsername);
        contextSource.setPassword(ldapPassword);
        contextSource.afterPropertiesSet();
        return contextSource;
    }

    @Bean
    public LdapTemplate ldapTemplate() {
        return new LdapTemplate(contextSource());
    }
}



