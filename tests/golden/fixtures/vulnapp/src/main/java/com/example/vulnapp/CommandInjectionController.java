package com.example.vulnapp;

import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CommandInjectionController {

    // EXPECT: command_injection — request input passed to Runtime.exec.
    @GetMapping("/cmd")
    public String run(@RequestParam String cmd) throws IOException {
        Runtime.getRuntime().exec(cmd);
        return "ok";
    }
}
