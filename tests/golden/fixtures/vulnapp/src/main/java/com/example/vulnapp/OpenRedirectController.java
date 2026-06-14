package com.example.vulnapp;

import java.io.IOException;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OpenRedirectController {

    // EXPECT: open_redirect — request input used as a redirect destination.
    @GetMapping("/redirect")
    public void redirect(@RequestParam String next, HttpServletResponse response) throws IOException {
        response.sendRedirect(next);
    }
}
