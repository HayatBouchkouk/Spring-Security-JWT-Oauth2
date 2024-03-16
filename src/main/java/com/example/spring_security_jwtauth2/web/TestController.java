package com.example.spring_security_jwtauth2.web;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class TestController {


    @GetMapping("/dataset")
    public Map<String,Object> dataset()
    {
        return Map.of("message","DATA TEST");
    }


}
