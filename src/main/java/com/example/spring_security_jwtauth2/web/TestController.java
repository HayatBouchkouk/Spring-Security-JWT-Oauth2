package com.example.spring_security_jwtauth2.web;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class TestController {


    @PreAuthorize("hasAuthority('SCOPE_USER')")
    @GetMapping("/dataset")
    public Map<String,Object> dataset(Authentication authentication)
    {
        return Map.of(
                "message", "DATA TEST",
                "username",authentication.getName(),
                "authorities",authentication.getAuthorities()
        );
    }

    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    @PostMapping("/saveData")
    public Map<String,String > saveData(Authentication authentication,String data)
    {
        return Map.of(
                "dataSaved",data

        );

    }


}
