package com.example.vulnapp;

import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LdapInjectionController {

    // EXPECT: ldap_injection — request input used as the LDAP search filter.
    @GetMapping("/ldap")
    public Object search(@RequestParam String user) throws Exception {
        DirContext ctx = new InitialDirContext();
        return ctx.search("ou=people", "(uid=" + user + ")", new SearchControls());
    }
}
