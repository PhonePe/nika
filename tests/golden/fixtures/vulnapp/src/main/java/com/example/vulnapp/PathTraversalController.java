package com.example.vulnapp;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PathTraversalController {

    // EXPECT: path_traversal — request input used to build a file path.
    @GetMapping("/file")
    public String read(@RequestParam String name) throws IOException {
        File file = new File(name);
        try (FileReader reader = new FileReader(file)) {
            return "read " + file.getPath();
        }
    }
}
