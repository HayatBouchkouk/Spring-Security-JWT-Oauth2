package com.example.spring_security_jwtauth2;

import com.example.spring_security_jwtauth2.config.RsaKeysConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.config.annotation.rsocket.RSocketSecurity;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeysConfig.class)
public class SpringSecurityJwtauth2Application {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityJwtauth2Application.class, args);
    }

}
