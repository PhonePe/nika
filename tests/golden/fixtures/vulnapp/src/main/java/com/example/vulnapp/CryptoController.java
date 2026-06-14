package com.example.vulnapp;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CryptoController {

    // EXPECT: cryptographic_failure — use of the broken MD5 hash algorithm.
    @GetMapping("/hash")
    public byte[] hash(@RequestParam String data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return digest.digest(data.getBytes());
    }
}
