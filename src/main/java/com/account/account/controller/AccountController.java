package com.account.account.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountController {

    @PostMapping("/myAccount")
    public ResponseEntity<String> getAccount() {
        return ResponseEntity.ok("Hello World");
    }
}
