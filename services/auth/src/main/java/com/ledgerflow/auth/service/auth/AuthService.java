package com.ledgerflow.auth.service.auth;

import com.ledgerflow.auth.domain.session.AuthSession;
import com.ledgerflow.auth.domain.session.SessionStatus;
import com.ledgerflow.auth.domain.user.AuthUser;
import com.ledgerflow.auth.repository.AuthSessionRepository;
import com.ledgerflow.auth.repository.AuthUserRepository;
import com.ledgerflow.auth.service.model.AuthTokens;
import com.ledgerflow.auth.service.token.JwtTokenService;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.util.UUID;

@Service
public class AuthService {
    private final AuthUserRepository authUserRepository;
    private final AuthSessionRepository authSessionRepository;
    private final JwtTokenService jwtTokenService;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;
    private final Duration refreshTokenTtl;

    public AuthService(AuthUserRepository authUserRepository, AuthSessionRepository authSessionRepository, JwtTokenService jwtTokenService, PasswordEncoder passwordEncoder, Clock clock, Duration refreshTokenTtl) {
        this.authUserRepository = authUserRepository;
        this.authSessionRepository = authSessionRepository;
        this.jwtTokenService = jwtTokenService;
        this.passwordEncoder = passwordEncoder;
        this.clock = clock;
        this.refreshTokenTtl = refreshTokenTtl;
    }

    @Transactional
    public AuthUser register(String login, String password) {
        if (authUserRepository.findByLogin(login).isPresent()) {
            throw new BadCredentialsException("User already exists");
        }

        String hashedPassword = passwordEncoder.encode(password);

        AuthUser user = AuthUser.create(login, hashedPassword);

        authUserRepository.save(user);

        return user;
    }

    @Transactional
    public AuthTokens login(String login, String password){
        AuthUser user = authUserRepository.findByLogin(login)
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        if(!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new BadCredentialsException("Invalid credentials");
        }

        AuthSession session = AuthSession.create(
                user,
                clock,
                refreshTokenTtl
        );

        String accessToken = jwtTokenService.generateAccessToken(user,session);
        String refreshToken = jwtTokenService.generateRefreshToken(session);

        session.attachRefreshToken(refreshToken, passwordEncoder);

        authSessionRepository.save(session);

        return new AuthTokens(accessToken, refreshToken);
    }

    @Transactional
    public void logout(String accessToken){
        if(!jwtTokenService.validateAccessToken(accessToken)){
            throw new BadCredentialsException("Invalid token");
        }

        UUID sessionId = jwtTokenService.extractSessionIdFromAccessToken(accessToken);

        authSessionRepository.findById(sessionId).ifPresent(session -> {
            if(session.getStatus() == SessionStatus.ACTIVE) {
                session.revoke();
            }
        });
    }

    @Transactional
    public void logoutAll(String accessToken){
        if(!jwtTokenService.validateAccessToken(accessToken)){
            throw new BadCredentialsException("Invalid token");
        }

        UUID userId = jwtTokenService.extractUserId(accessToken);

        authSessionRepository.revokeAllActiveByUserId(userId);
    }

    @Transactional
    public AuthTokens refresh(String refreshToken){
        if(!jwtTokenService.validateRefreshToken(refreshToken)) {
            throw new BadCredentialsException("Invalid refresh token");
        }

        UUID sessionId = jwtTokenService.extractSessionId(refreshToken);

        AuthSession session = authSessionRepository.findById(sessionId)
                .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));

        if(session.getStatus() != SessionStatus.ACTIVE) {
            throw new BadCredentialsException("Token revoked");
        }

        if(session.getExpiresAt().isBefore(clock.instant())){
            throw new BadCredentialsException("Session expired");
        }

        if(!passwordEncoder.matches(refreshToken, session.getRefreshTokenHash())){
            throw new BadCredentialsException("Invalid refresh token");
        }

        AuthUser user = session.getUser();

        String newAccessToken = jwtTokenService.generateAccessToken(user, session);
        String newRefreshToken = jwtTokenService.generateRefreshToken(session);

        session.attachRefreshToken(newRefreshToken,passwordEncoder);
        authSessionRepository.save(session);

        return new AuthTokens(newAccessToken,newRefreshToken);
    }
 }


