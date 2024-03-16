package com.example.spring_security_jwtauth2.config;


import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.FilterChain;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.OAuth2ResourceServerDsl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SpringConfig {

    private final RsaKeysConfig rsaKeysConfig;


    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager()
    {

        return new InMemoryUserDetailsManager(
                User.withUsername("user1").password("{noop}123").authorities("USER").build(),
                User.withUsername("user2").password("{noop}123").authorities("USER").build(),
                User.withUsername("admin").password("{noop}123").authorities("ADMIN","USER").build()
        );
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
     return     httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth-> auth.anyRequest().authenticated())
                .sessionManagement(sess->sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                 .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
                 .httpBasic(Customizer.withDefaults())
                 //.formLogin(Customizer.withDefaults())
                .build();


    }

    @Bean
    JwtDecoder jwtDecoder(){
        return NimbusJwtDecoder.withPublicKey(rsaKeysConfig.rsaPublicKey()).build();
    }
    @Bean
    JwtEncoder jwtEncoder(){
        JWK jwk= new RSAKey.Builder(rsaKeysConfig.rsaPublicKey()).privateKey(rsaKeysConfig.rsaPrivateKey()).build();
        JWKSource<SecurityContext> jwkSource= new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }
}
