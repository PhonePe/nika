package com.example.vulnapp.safe;

import java.util.List;
import javax.persistence.EntityManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SafeSqlController {

    private EntityManager entityManager;

    // SAFE: parameterized query — request input is bound, never concatenated into the JPQL.
    // Must NOT be reported as sql_injection.
    @GetMapping("/safe/sql")
    public List<?> find(@RequestParam String name) {
        return entityManager
                .createQuery("SELECT u FROM User u WHERE u.name = :name")
                .setParameter("name", name)
                .getResultList();
    }
}
