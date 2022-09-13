package com.johnjohn.openid.javaopenid.resources;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StatusResource {

    @GetMapping(value = "/status")
    public ResponseEntity<String> get() {
        return ResponseEntity.ok("STATUS: OK");
    }

}
