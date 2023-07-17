package com.example.security.auth;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class DemoController {

    @GetMapping("/demoController")
    public ResponseEntity<String> welcome(){
        return ResponseEntity.ok("Hello from a secured endPoint");
    }
}
