package com.example.vulnapp;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class XpathInjectionController {

    // EXPECT: xpath_injection — request input compiled into an XPath expression.
    @GetMapping("/xpath")
    public Object query(@RequestParam String expr) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        return xpath.compile("/users/user[name='" + expr + "']");
    }
}
