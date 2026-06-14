package com.example.vulnapp;

import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.Query;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SqlInjectionController {

    private EntityManager entityManager;

    // EXPECT: sql_injection — request input concatenated into a JPQL query.
    @GetMapping("/sqli")
    public List<?> find(@RequestParam String name) {
        Query query = entityManager.createQuery("SELECT u FROM User u WHERE u.name = " + name);
        return query.getResultList();
    }
}
