package com.example.vulnapp;

import org.bson.Document;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NoSqlInjectionController {

    // EXPECT: nosql_injection — request input parsed into a Mongo query document.
    @GetMapping("/nosql")
    public Object query(@RequestParam String filter) {
        Document query = Document.parse(filter);
        return query.toJson();
    }
}
