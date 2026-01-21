package com.ledgerflow.auth.config;

import io.jsonwebtoken.security.Keys;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

@Configuration
public class SecurityBeansConfig {
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecretKey accessTokenKey(){
        return Keys.hmacShaKeyFor(
                "access-token-secret-key-at-least-32-bytes".getBytes(StandardCharsets.UTF_8)
        );
    }

    @Bean
    public SecretKey refreshTokenKey(){
        return Keys.hmacShaKeyFor(
          "refresh-token-secret-key-at-least-32-bytes".getBytes(StandardCharsets.UTF_8)
        );
    }

    @Bean
    public Duration accessTokenTtl(){
        return Duration.ofMinutes(15);
    }

    @Bean
    public Duration refreshTokenTtl(){
        return Duration.ofDays(7);
    }
}
