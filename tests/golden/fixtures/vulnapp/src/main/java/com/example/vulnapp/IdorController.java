package com.example.vulnapp;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IdorController {

    // EXPECT: idor — resource fetched by a caller-supplied id with no ownership check.
    @GetMapping("/users/{userId}")
    public String get(@PathVariable Long userId) {
        return "user-" + userId;
    }
}
