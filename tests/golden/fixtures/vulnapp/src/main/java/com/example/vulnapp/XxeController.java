package com.example.vulnapp;

import java.io.ByteArrayInputStream;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.xml.sax.helpers.DefaultHandler;

@RestController
public class XxeController {

    // EXPECT: xxe — request body parsed by a SAX parser without disabling external entities.
    @PostMapping("/xml")
    public String parse(@RequestBody String body) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser parser = factory.newSAXParser();
        parser.parse(new ByteArrayInputStream(body.getBytes()), new DefaultHandler());
        return "parsed";
    }
}
