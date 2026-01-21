package com.ledgerflow.auth.service.token;

import com.ledgerflow.auth.domain.session.AuthSession;
import com.ledgerflow.auth.domain.user.AuthUser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtTokenService implements TokenService {
    private final Clock clock;

    private final SecretKey accessTokenKey;
    private final Duration accessTokenTtl;

    private final SecretKey refreshTokenKey;
    private final Duration refreshTokenTtl;

    public JwtTokenService(Clock clock, SecretKey accessTokenKey, Duration accessTokenTtl, SecretKey refreshTokenKey, Duration refreshTokenTtl) {
        this.clock = clock;
        this.accessTokenKey = accessTokenKey;
        this.accessTokenTtl = accessTokenTtl;
        this.refreshTokenKey = refreshTokenKey;
        this.refreshTokenTtl = refreshTokenTtl;
    }

    @Override
    public String generateAccessToken(AuthUser user, AuthSession session) {
        Instant now = clock.instant();
        Instant expiresAt = now.plus(accessTokenTtl);

        return Jwts.builder()
                .setSubject(user.getId().toString())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(expiresAt))
                .claim("sessionId",session.getId().toString())
                .claim("status", user.getStatus().name())
                .signWith(accessTokenKey, SignatureAlgorithm.HS256)
                .compact();
    }

    @Override
    public String generateRefreshToken(AuthSession session) {
        Instant now = clock.instant();
        return Jwts.builder()
                .setSubject(session.getId().toString())
                .setIssuedAt(Date.from(now))
                .signWith(refreshTokenKey,SignatureAlgorithm.HS256)
                .compact();
    }

    @Override
    public boolean validateAccessToken(String accessToken) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(accessTokenKey)
                    .build()
                    .parseClaimsJws(accessToken);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean validateRefreshToken(String refreshToken) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(refreshTokenKey)
                    .build()
                    .parseClaimsJws(refreshToken);
            return true;
        } catch (Exception e) {
            return  false;
        }
    }

    @Override
    public UUID extractUserId(String accessToken) {
        String userId = Jwts.parserBuilder()
                .setSigningKey(accessTokenKey)
                .build()
                .parseClaimsJws(accessToken)
                .getBody()
                .getSubject();
        return UUID.fromString(userId);
    }

    public UUID extractSessionIdFromAccessToken(String accessToken){
        String sessionId = Jwts.parserBuilder()
                .setSigningKey(accessTokenKey)
                .build()
                .parseClaimsJws(accessToken)
                .getBody()
                .get("sessionId", String.class);

        return UUID.fromString(sessionId);
    }

    @Override
    public UUID extractSessionId(String refreshToken) {
        String sessionId = Jwts.parserBuilder()
                .setSigningKey(refreshTokenKey)
                .build()
                .parseClaimsJws(refreshToken)
                .getBody()
                .getSubject();

        return UUID.fromString(sessionId);
    }


}
