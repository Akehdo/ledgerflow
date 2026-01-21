package com.ledgerflow.auth.service.token;

import com.ledgerflow.auth.domain.session.AuthSession;
import com.ledgerflow.auth.domain.user.AuthUser;

import java.util.UUID;

public interface TokenService {
    String generateAccessToken(AuthUser user, AuthSession session);
    String generateRefreshToken(AuthSession session);

    boolean validateAccessToken(String accessToken);
    boolean validateRefreshToken(String refreshToken);

    UUID extractUserId(String accessToken);
    UUID extractSessionId(String refreshToken);
}
