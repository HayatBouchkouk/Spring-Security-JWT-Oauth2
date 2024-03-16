package com.example.spring_security_jwtauth2.web;


import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthController {

    private final JwtEncoder jwtEncoder;



    //this post will generate the token of authenticated user!
    @PostMapping("/token")
    public Map<String,String> jwtToken(Authentication authentication)
    {

        Instant instant=Instant.now();

        String scope=authentication.getAuthorities()
                .stream().map(auth->authentication.getName()).collect(Collectors.joining(" "));

        JwtClaimsSet jwtClaimsSet=JwtClaimsSet.builder()
                .subject(authentication.getName())
                .issuedAt(instant)
                .expiresAt(instant.plus(5, ChronoUnit.MINUTES))
                .issuer("security-service")
                .claim("scope",scope)
                .build();

        String jwtAccessToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();

        Map<String,String> IdToken=new HashMap<>();

        IdToken.put("accessToken",jwtAccessToken);

        return IdToken;
    }

}
