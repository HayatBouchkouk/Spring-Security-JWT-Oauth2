package com.example.spring_security_jwtauth2.web;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
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
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final JwtEncoder jwtEncoder;

    private final AuthenticationManager authenticationManager;
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);


    //this post will generate the token of authenticated user!

    @PostMapping("/token")
    public Map<String, String> jwtToken
            (String grantType,
             String username,
             String password,
             boolean withRefreshToken,
             String refreshToken) {


        Authentication authentication=null;

        if (grantType.equals("password")) {

            try {
                authentication = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(username, password)
                );

            } catch (AuthenticationException e) {
                // Authentication failed
                // You can log authentication failure here or handle the exception as needed
                LOGGER.error("Authentication failed for user '{}': {}", username, e.getMessage());
                throw e; // Rethrow the exception or handle it based on your requirements
            }

        }

        else if (grantType.equals("refreshToken"))
        {

        }




            // User successfully authenticated
            // You can log authentication success here if needed
            LOGGER.info("User '{}' successfully authenticated", username);

            // Generate JWT token
            Instant instant = Instant.now();
            String scope = authentication.getAuthorities()
                    .stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(" "));

            JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                    .subject(authentication.getName())
                    .issuedAt(instant)
                    .expiresAt(instant.plus(withRefreshToken ? 5 : 30, ChronoUnit.MINUTES))
                    .issuer("security-service")
                    .claim("scope", scope)
                    .build();

            String jwtAccessToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();

            Map<String, String> idToken = new HashMap<>();
            idToken.put("accessToken", jwtAccessToken);

            if (withRefreshToken)
            {

                // Generate Refresh Token token
                JwtClaimsSet jwtClaimsSetRefresh = JwtClaimsSet.builder()
                        .subject(authentication.getName())
                        .issuedAt(instant)
                        .expiresAt(instant.plus(30, ChronoUnit.MINUTES))
                        .issuer("security-service")
                        .build();

                String jwtRefreshToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetRefresh)).getTokenValue();
                idToken.put("RefreshToken",jwtRefreshToken);
            }

            return idToken;

    }

}
