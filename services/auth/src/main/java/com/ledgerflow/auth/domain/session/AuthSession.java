package com.ledgerflow.auth.domain.session;

import com.ledgerflow.auth.domain.user.AuthUser;
import jakarta.persistence.*;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "auth_sessions")
public class AuthSession {

    @Id
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    public SessionStatus getStatus() {
        return status;
    }

    public UUID getId() {
        return id;
    }

    public AuthUser getUser() {
        return user;
    }

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private AuthUser user;

    @Column(name = "refresh_token_hash", nullable = true)
    private String refreshTokenHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private SessionStatus status;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    protected AuthSession() {
        // JPA only
    }

    public static AuthSession create(AuthUser user, Clock clock, Duration ttl) {
        AuthSession session = new AuthSession();
        session.id = UUID.randomUUID();
        session.user = user;
        session.status = SessionStatus.ACTIVE;
        session.createdAt = clock.instant();
        session.expiresAt = session.createdAt.plus(ttl);

        return session;
    }

    public void attachRefreshToken(String refreshToken, PasswordEncoder encoder){

        this.refreshTokenHash = encoder.encode(refreshToken);
    }

    public void revoke() {
        this.status = SessionStatus.REVOKED;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AuthSession)) return false;
        return id != null && id.equals(((AuthSession) o).id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }

    public String getRefreshTokenHash() {
        return refreshTokenHash;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}
