package com.example.vulnapp;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DeserializationController {

    // EXPECT: deserialization — request bytes deserialized via ObjectInputStream.readObject.
    @PostMapping("/deser")
    public Object deser(@RequestBody byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }
}
