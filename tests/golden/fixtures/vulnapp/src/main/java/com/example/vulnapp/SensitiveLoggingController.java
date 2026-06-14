package com.example.vulnapp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SensitiveLoggingController {

    private static final Logger log = LoggerFactory.getLogger(SensitiveLoggingController.class);

    // EXPECT: sensitive_logging — a password value written to the log.
    @GetMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        log.info("login attempt username=" + username + " password=" + password);
        return "ok";
    }
}
