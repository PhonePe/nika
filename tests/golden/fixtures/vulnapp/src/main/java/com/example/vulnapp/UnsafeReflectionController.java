package com.example.vulnapp;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UnsafeReflectionController {

    // EXPECT: unsafe_reflection — request input selects the class to load.
    @GetMapping("/reflect")
    public Object load(@RequestParam String className) throws Exception {
        Class<?> clazz = Class.forName(className);
        return clazz.getName();
    }
}
