package com.example.vulnapp;

import java.io.IOException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SsrfController {

    // EXPECT: ssrf — request input used as the URL of an outbound HTTP request.
    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) throws IOException {
        HttpClient client = HttpClients.createDefault();
        HttpGet request = new HttpGet(url);
        client.execute(request);
        return "fetched";
    }
}
