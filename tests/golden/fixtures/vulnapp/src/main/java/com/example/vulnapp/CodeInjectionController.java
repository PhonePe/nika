package com.example.vulnapp;

import org.mvel2.MVEL;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CodeInjectionController {

    // EXPECT: code_injection — request input evaluated as an MVEL expression.
    @GetMapping("/eval")
    public Object eval(@RequestParam String expr) {
        return MVEL.executeExpression(expr);
    }
}
