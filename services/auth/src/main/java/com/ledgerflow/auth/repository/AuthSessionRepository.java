package com.ledgerflow.auth.repository;

import com.ledgerflow.auth.domain.session.AuthSession;
import com.ledgerflow.auth.domain.session.SessionStatus;
import com.ledgerflow.auth.domain.user.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface AuthSessionRepository extends JpaRepository<AuthSession, UUID> {
    Optional<AuthSession> findByRefreshTokenHash(String refreshTokenHash);

    @Modifying(clearAutomatically = true,flushAutomatically = true)
    @Query("""
    update AuthSession s 
        set s.status = 'REVOKED'
        where s.user.id = :userId
            and s.status = 'ACTIVE'
    """)
    void revokeAllActiveByUserId(@Param("userId")UUID userId);

}
