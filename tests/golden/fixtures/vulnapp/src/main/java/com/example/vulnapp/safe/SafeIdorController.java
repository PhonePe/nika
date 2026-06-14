package com.example.vulnapp.safe;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SafeIdorController {

    // SAFE: the path id is checked against the authenticated principal before use.
    // Must NOT be reported as idor (ownership check present).
    @GetMapping("/safe/users/{userId}")
    public String get(@PathVariable Long userId) {
        Long current = SecurityUtils.getCurrentUserId();
        if (!current.equals(userId)) {
            throw new RuntimeException("forbidden");
        }
        return "user-" + userId;
    }
}
