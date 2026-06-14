package com.example.vulnapp;

import java.io.StringReader;
import com.github.mustachejava.DefaultMustacheFactory;
import com.github.mustachejava.Mustache;
import com.github.mustachejava.MustacheFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TemplateInjectionController {

    // EXPECT: template_injection — request input compiled as a Mustache template.
    @GetMapping("/template")
    public String render(@RequestParam String tmpl) {
        MustacheFactory factory = new DefaultMustacheFactory();
        Mustache mustache = factory.compile(new StringReader(tmpl), "inline");
        return mustache.getName();
    }
}
